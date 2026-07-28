#include "std_include.hpp"
#include "syscall_dispatcher.hpp"
#include "syscall_utils.hpp"

#include <utils/string.hpp>

namespace sogen
{

    static void serialize(utils::buffer_serializer& buffer, const syscall_handler_entry& obj)
    {
        buffer.write(obj.name);
    }

    static void deserialize(utils::buffer_deserializer& buffer, syscall_handler_entry& obj)
    {
        buffer.read(obj.name);
        obj.handler = nullptr;
    }

    void syscall_dispatcher::serialize(utils::buffer_serializer& buffer) const
    {
        buffer.write_map(this->handlers_);
    }

    void syscall_dispatcher::deserialize(utils::buffer_deserializer& buffer)
    {
        buffer.read_map(this->handlers_);
        this->add_handlers();
        this->add_callbacks();
    }

    void syscall_dispatcher::setup(const exported_symbols& ntdll_exports, const std::span<const std::byte> ntdll_data,
                                   const exported_symbols& win32u_exports, const std::span<const std::byte> win32u_data)
    {
        this->handlers_ = {};

        const auto ntdll_syscalls = find_syscalls(ntdll_exports, ntdll_data);
        const auto win32u_syscalls = find_syscalls(win32u_exports, win32u_data);

        map_syscalls(this->handlers_, ntdll_syscalls);
        map_syscalls(this->handlers_, win32u_syscalls);

        this->add_handlers();
        this->add_callbacks();
    }

    void syscall_dispatcher::add_handlers()
    {
        std::map<std::string, syscall_handler> handler_mapping{};
        syscall_dispatcher::add_handlers(handler_mapping);

        for (auto& entry : this->handlers_ | std::views::values)
        {
            const auto handler = handler_mapping.find(entry.name);
            if (handler == handler_mapping.end())
            {
                continue;
            }

            entry.handler = handler->second;

#ifndef NDEBUG
            handler_mapping.erase(handler);
#endif
        }
    }

    void syscall_dispatcher::dispatch(windows_emulator& win_emu, vcpu_context& vcpu)
    {
        auto& emu = vcpu.cpu;
        auto& context = win_emu.process;

        const auto address = emu.read_instruction_pointer();
        const auto raw_syscall_id = emu.reg<uint32_t>(x86_register::eax);
        const auto syscall_id = raw_syscall_id & 0x3FFF; // Only take low bits for WOW64 compatibility, match windoows wraparound

        const auto entry = this->handlers_.find(syscall_id);
        const auto* syscall_name = (entry != this->handlers_.end()) ? entry->second.name.c_str() : "<unknown>";

        const syscall_context c{
            .win_emu = win_emu,
            .emu = emu,
            .vcpu = vcpu,
            .proc = context,
            .write_status = true,
        };

        try
        {
            if (entry == this->handlers_.end())
            {
                // Windows does NOT terminate the process on a bogus syscall number: the
                // kernel returns STATUS_INVALID_SYSTEM_SERVICE and execution resumes at
                // the instruction after `syscall`.
                //
                // Theia depends on exactly that. runtime.dll RVA 0x898380 is:
                //     31 c0              xor  eax, eax
                //     8b 00              mov  eax, [rax]     ; deliberate null-read fault
                //     b8 ff 0f 00 00     mov  eax, 0FFFh     ; deliberately bogus SSN
                //     0f 05              syscall
                //     c3                 ret
                // a fault-then-invalid-syscall anti-emulation probe. Calling stop() here
                // fails the probe and kills the run before the packer ever gets going.
                //
                // An id ABOVE the highest service we know about cannot be a real service,
                // so mimic the kernel and continue. An id inside the known range that we
                // simply lack is still a genuine gap, and keeps failing loudly.
                // (A range guard is useless here: handlers_ also holds win32k ids >= 0x1000,
                //  so 0xFFF is not "out of range". Windows returns the error for ANY id that
                //  is absent from the SSDT, so do the same unconditionally -- log loudly, but
                //  do NOT stop. Genuine gaps stay visible in the log as "Unknown syscall".)
                win_emu.log.error("Unknown syscall: 0x%X (raw: 0x%X) -> STATUS_INVALID_SYSTEM_SERVICE (continuing)\n",
                                  syscall_id, raw_syscall_id);
                c.emu.reg<uint64_t>(x86_register::rax, STATUS_INVALID_SYSTEM_SERVICE);
                return;
            }

            const auto res = win_emu.callbacks.on_syscall(syscall_id, entry->second.name);
            if (res == instruction_hook_continuation::skip_instruction)
            {
                return;
            }

            if (!entry->second.handler)
            {
                win_emu.log.error("Unimplemented syscall: %s - 0x%X (raw: 0x%X)\n", entry->second.name.c_str(), syscall_id, raw_syscall_id);
                win_emu.record_stop(stop_reason::unimplemented_syscall, entry->second.name);
                c.emu.reg<uint64_t>(x86_register::rax, STATUS_NOT_SUPPORTED);
                win_emu.stop();
                return;
            }

            entry->second.handler(c);

            // DIAGNOSTIC: Theia aborts init with a message box reading
            // "The program encountered C00000BB at 0159421E during initialization."
            // C00000BB is STATUS_NOT_SUPPORTED, so report every syscall that returns it.
            {
                const auto ret = emu.reg<uint64_t>(x86_register::rax);
                // Any NT error status (severity 0b11). Theia reports several verbatim in its
                // own dialogs, and the ones that matter are not just STATUS_NOT_SUPPORTED
                // (0xC00000BB) / STATUS_INVALID_CID (0xC000000B) -- a child failing to map
                // its inherited section returns STATUS_INVALID_HANDLE (0xC0000008).
                if ((ret & 0xFFFFFFFFull) >= 0xC0000000ull && ret <= 0xFFFFFFFFull)
                {
                    win_emu.log.print(color::red, "[FAILRET] %s (0x%X) returned 0x%" PRIx64 " at 0x%" PRIx64 "\n",
                                      entry->second.name.c_str(), syscall_id, ret, address);
                }
            }

            dispatch_callback(win_emu, entry->second.name);
        }
        catch (std::exception& e)
        {
            win_emu.log.error("Syscall %s threw an exception: 0x%X (raw: 0x%X) (0x%" PRIx64 ") - %s\n", syscall_name, syscall_id,
                              raw_syscall_id, address, e.what());
            win_emu.record_stop(stop_reason::syscall_exception, std::string(syscall_name) + ": " + e.what());
            emu.reg<uint64_t>(x86_register::rax, STATUS_UNSUCCESSFUL);
            win_emu.stop();
        }
        catch (...)
        {
            win_emu.log.error("Syscall %s threw an unknown exception: 0x%X (raw: 0x%X) (0x%" PRIx64 ")\n", syscall_name, syscall_id,
                              raw_syscall_id, address);
            win_emu.record_stop(stop_reason::syscall_exception, std::string(syscall_name) + ": <unknown exception>");
            emu.reg<uint64_t>(x86_register::rax, STATUS_UNSUCCESSFUL);
            win_emu.stop();
        }
    }

    void syscall_dispatcher::dispatch_callback(windows_emulator& win_emu, std::string& syscall_name)
    {
        // active_cpu(), not emu(): this runs under the syscall's scoped_dispatch, and with more than one
        // vCPU the instrumentation-callback redirect must rewrite the acting vCPU's RIP/r10, not vCPU 0's.
        auto& emu = win_emu.active_cpu();
        auto& context = win_emu.process;

        if (context.instrumentation_callback != 0 && syscall_name != "NtContinue")
        {
            auto rip_old = emu.reg<uint64_t>(x86_register::rip);

            // The original code always subtracted 2, assuming the backend has NOT yet
            // advanced RIP past the 2-byte `syscall` and will add it after this hook.
            // That holds for unicorn/icicle but NOT for WHP, where RIP is already past
            // the instruction. Under WHP the compensation lands 2 bytes early -- and when
            // Theia's callback sits directly after its own syscall, those 2 bytes ARE the
            // `syscall`, so it re-executes forever with whatever stale value is left in
            // eax (observed: repeated dispatches at one rip, raw ids 0x0/0x8/0xC0000008).
            //
            // Decide empirically instead of per-backend: if RIP still points at `0F 05`
            // the backend has not advanced yet.
            bool rip_still_at_syscall = false;
            try
            {
                rip_still_at_syscall = (emu.read_memory<uint16_t>(rip_old) == 0x050F);
            }
            catch (...)
            {
            }

            // Windows hands the callback the RETURN address (after the syscall) in r10.
            const auto return_rip = rip_still_at_syscall ? rip_old + 2 : rip_old;

            emu.reg<uint64_t>(x86_register::rip, rip_still_at_syscall
                                                     ? context.instrumentation_callback - 2
                                                     : context.instrumentation_callback);

            emu.reg<uint64_t>(x86_register::r10, return_rip);
        }
    }

    dispatch_result syscall_dispatcher::dispatch_completion(windows_emulator& win_emu, vcpu_context& vcpu, callback_id callback_id,
                                                            completion_state* completion_state, const user_callback_result& callback_result)
    {
        auto& emu = vcpu.cpu;

        const syscall_context c{.win_emu = win_emu,
                                .emu = emu,
                                .vcpu = vcpu,
                                .proc = win_emu.process,
                                .write_status = true,
                                .is_callback_completion = true,
                                .current_completion_state = completion_state,
                                .previous_callback_result = callback_result};

        const auto entry = this->completion_handlers_.find(callback_id);

        if (entry == this->completion_handlers_.end())
        {
            win_emu.log.error("Unknown callback: 0x%X\n", static_cast<uint32_t>(callback_id));
            win_emu.stop();
            return dispatch_result::error;
        }

        try
        {
            entry->second(c);
            return c.run_callback ? dispatch_result::new_callback : dispatch_result::completed;
        }
        catch (std::exception& e)
        {
            win_emu.log.error("Completion for callback 0x%X threw an exception - %s\n", static_cast<int>(callback_id), e.what());
            win_emu.stop();
            return dispatch_result::error;
        }
        catch (...)
        {
            win_emu.log.error("Completion for callback 0x%X threw an unknown exception\n", static_cast<int>(callback_id));
            win_emu.stop();
            return dispatch_result::error;
        }
    }

    syscall_dispatcher::syscall_dispatcher(const exported_symbols& ntdll_exports, const std::span<const std::byte> ntdll_data,
                                           const exported_symbols& win32u_exports, const std::span<const std::byte> win32u_data)
    {
        this->setup(ntdll_exports, ntdll_data, win32u_exports, win32u_data);
    }

    std::map<callback_id, std::function<std::unique_ptr<completion_state>()>> syscall_dispatcher::completion_state_factories_{};

} // namespace sogen
