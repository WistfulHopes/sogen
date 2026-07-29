#include "../std_include.hpp"

#include <set>
#include "../cpu_context.hpp"
#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"

#include <algorithm>
#include <utils/finally.hpp>

namespace sogen
{

    namespace syscalls
    {
        NTSTATUS handle_NtSetInformationThread(const syscall_context& c, const handle thread_handle, const THREADINFOCLASS info_class,
                                               const uint64_t thread_information, const uint32_t thread_information_length)
        {
            auto* thread = thread_handle == CURRENT_THREAD ? c.vcpu.active_thread : c.proc.threads.get(thread_handle);

            if (!thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (info_class == ThreadWow64Context)
            {
                // ThreadWow64Context is only valid for WOW64 processes
                if (!c.proc.is_wow64_process)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (thread_information_length != sizeof(WOW64_CONTEXT))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                // Check if thread has persistent WOW64 context
                if (!thread->wow64_cpu_reserved.has_value())
                {
                    c.win_emu.log.print(color::red, "Error: WOW64 saved context not initialized for thread %d\n", thread->id);
                    return STATUS_INTERNAL_ERROR;
                }

                const emulator_object<WOW64_CONTEXT> context_obj{c.emu, thread_information};
                const auto new_wow64_context = context_obj.read();

                // Update the persistent context for future queries
                thread->wow64_cpu_reserved->access([&](WOW64_CPURESERVED& ctx) {
                    ctx.Flags |= WOW64_CPURESERVED_FLAG_RESET_STATE;
                    auto merged_context = ctx.Context;
                    merged_context.ContextFlags = new_wow64_context.ContextFlags;

                    if ((new_wow64_context.ContextFlags & CONTEXT_DEBUG_REGISTERS_32) == CONTEXT_DEBUG_REGISTERS_32)
                    {
                        merged_context.Dr0 = new_wow64_context.Dr0;
                        merged_context.Dr1 = new_wow64_context.Dr1;
                        merged_context.Dr2 = new_wow64_context.Dr2;
                        merged_context.Dr3 = new_wow64_context.Dr3;
                        merged_context.Dr6 = new_wow64_context.Dr6;
                        merged_context.Dr7 = new_wow64_context.Dr7;
                    }

                    if ((new_wow64_context.ContextFlags & CONTEXT_FLOATING_POINT_32) == CONTEXT_FLOATING_POINT_32 &&
                        (new_wow64_context.FloatSave.ControlWord & 0x3F) == 0x3F)
                    {
                        merged_context.FloatSave = new_wow64_context.FloatSave;
                    }

                    if ((new_wow64_context.ContextFlags & CONTEXT_SEGMENTS_32) == CONTEXT_SEGMENTS_32)
                    {
                        merged_context.SegGs = new_wow64_context.SegGs;
                        merged_context.SegFs = new_wow64_context.SegFs;
                        merged_context.SegEs = new_wow64_context.SegEs;
                        merged_context.SegDs = new_wow64_context.SegDs;
                    }

                    if ((new_wow64_context.ContextFlags & CONTEXT_INTEGER_32) == CONTEXT_INTEGER_32)
                    {
                        merged_context.Edi = new_wow64_context.Edi;
                        merged_context.Esi = new_wow64_context.Esi;
                        merged_context.Ebx = new_wow64_context.Ebx;
                        merged_context.Edx = new_wow64_context.Edx;
                        merged_context.Ecx = new_wow64_context.Ecx;
                        merged_context.Eax = new_wow64_context.Eax;
                    }

                    if ((new_wow64_context.ContextFlags & CONTEXT_CONTROL_32) == CONTEXT_CONTROL_32)
                    {
                        merged_context.Ebp = new_wow64_context.Ebp;
                        merged_context.Eip = new_wow64_context.Eip;
                        merged_context.SegCs = new_wow64_context.SegCs;
                        merged_context.EFlags = new_wow64_context.EFlags;
                        merged_context.Esp = new_wow64_context.Esp;
                        merged_context.SegSs = new_wow64_context.SegSs;
                    }

                    if ((new_wow64_context.ContextFlags & CONTEXT_EXTENDED_REGISTERS_32) == CONTEXT_EXTENDED_REGISTERS_32)
                    {
                        const uint16_t incoming_ext_cw = static_cast<uint16_t>(new_wow64_context.ExtendedRegisters[0]) |
                                                         (static_cast<uint16_t>(new_wow64_context.ExtendedRegisters[1]) << 8);
                        if ((incoming_ext_cw & 0x3F) == 0x3F)
                        {
                            memcpy(merged_context.ExtendedRegisters, new_wow64_context.ExtendedRegisters,
                                   sizeof(merged_context.ExtendedRegisters));
                        }
                    }

                    ctx.Context = merged_context;
                    // c.win_emu.callbacks.on_suspicious_activity("WOW64 CONTEXT");
                });

                // Debug registers are real CPU state (shared between 32/64-bit), not part of the
                // WOW64_CPURESERVED block that wow64cpu reloads on resume. They must be programmed into
                // the VP directly, otherwise a 32-bit hardware breakpoint armed via the thread context
                // (e.g. t6r's CEG single-step trick) never arms and never fires.
                if ((new_wow64_context.ContextFlags & CONTEXT_DEBUG_REGISTERS_32) == CONTEXT_DEBUG_REGISTERS_32)
                {
                    const bool needs_switch = thread != c.vcpu.active_thread;
                    if (needs_switch)
                    {
                        c.vcpu.active_thread->save(c.emu);
                        thread->restore(c.emu);
                    }

                    c.emu.reg(x86_register::dr0, static_cast<uint64_t>(new_wow64_context.Dr0));
                    c.emu.reg(x86_register::dr1, static_cast<uint64_t>(new_wow64_context.Dr1));
                    c.emu.reg(x86_register::dr2, static_cast<uint64_t>(new_wow64_context.Dr2));
                    c.emu.reg(x86_register::dr3, static_cast<uint64_t>(new_wow64_context.Dr3));
                    c.emu.reg(x86_register::dr6, static_cast<uint64_t>(new_wow64_context.Dr6));
                    c.emu.reg(x86_register::dr7, static_cast<uint64_t>(new_wow64_context.Dr7));

                    if (needs_switch)
                    {
                        thread->save(c.emu);
                        c.vcpu.active_thread->restore(c.emu);
                    }
                }

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadSchedulerSharedDataSlot || info_class == ThreadBasePriority || info_class == ThreadAffinityMask ||
                info_class == ThreadPriorityBoost || info_class == ThreadEnableAlignmentFaultFixup)
            {
                return STATUS_SUCCESS;
            }

            if (info_class == ThreadHideFromDebugger)
            {
                BOOLEAN hide = true;

                if (thread_information != 0 && thread_information % 4 != 0)
                {
                    return STATUS_DATATYPE_MISALIGNMENT;
                }

                if (thread_information_length == 0 || thread_information_length == sizeof(hide))
                {
                    if (thread_information_length == sizeof(hide))
                    {
                        if (thread_information == 0 || !c.win_emu.memory.try_read_memory(thread_information, &hide, sizeof(hide)))
                        {
                            return STATUS_INTERNAL_ERROR;
                        }
                    }

                    c.thread().debugger_hide = hide;
                    c.win_emu.callbacks.on_suspicious_activity("Hiding thread from debugger");
                    return STATUS_SUCCESS;
                }

                return STATUS_INFO_LENGTH_MISMATCH;
            }

            if (info_class == ThreadNameInformation)
            {
                if (thread_information_length != sizeof(THREAD_NAME_INFORMATION<EmulatorTraits<Emu64>>))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<THREAD_NAME_INFORMATION<EmulatorTraits<Emu64>>> info{c.emu, thread_information};
                const auto i = info.read();
                thread->name = read_unicode_string(c.emu, i.ThreadName);

                c.win_emu.callbacks.on_thread_set_name(*thread);

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadImpersonationToken)
            {
                if (thread_information_length != sizeof(handle))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<handle> info{c.emu, thread_information};
                info.write(DUMMY_IMPERSONATION_TOKEN);

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadZeroTlsCell)
            {
                if (thread_information_length != sizeof(ULONG))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const auto tls_cell = c.emu.read_memory<ULONG>(thread_information);

                for (const auto& t : c.proc.threads | std::views::values)
                {
                    if (tls_cell < TLS_MINIMUM_AVAILABLE)
                    {
                        if (c.proc.is_wow64_process)
                        {
                            if (t.teb32.has_value())
                            {
                                t.teb32->access([&](TEB32& teb32) { teb32.TlsSlots.arr[tls_cell] = 0; });
                            }
                        }
                        else
                        {
                            t.teb64->access([&](TEB64& teb64) { teb64.TlsSlots.arr[tls_cell] = 0; });
                        }
                    }
                    else if (tls_cell < TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS)
                    {
                        if (c.proc.is_wow64_process)
                        {
                            if (t.teb32.has_value())
                            {
                                t.teb32->access([&](TEB32& teb32) {
                                    if (teb32.TlsExpansionSlots)
                                    {
                                        c.emu.write_memory<uint32_t>(teb32.TlsExpansionSlots + (4 * tls_cell) - TLS_MINIMUM_AVAILABLE, 0);
                                    }
                                });
                            }
                        }
                        else
                        {
                            t.teb64->access([&](TEB64& teb64) {
                                if (teb64.TlsExpansionSlots)
                                {
                                    c.emu.write_memory<uint64_t>(teb64.TlsExpansionSlots + (8 * tls_cell) - TLS_MINIMUM_AVAILABLE, 0);
                                }
                            });
                        }
                    }
                }

                return STATUS_SUCCESS;
            }

            c.win_emu.log.error("Unsupported thread set info class: %X\n", info_class);
            c.emu.stop();
            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtQueryInformationThread(const syscall_context& c, const handle thread_handle, const uint32_t info_class,
                                                 const uint64_t thread_information, const uint32_t thread_information_length,
                                                 const emulator_object<uint32_t> return_length)
        {
            const auto* thread = thread_handle == CURRENT_THREAD ? c.vcpu.active_thread : c.proc.threads.get(thread_handle);

            if (!thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            emulator_thread& cur_emulator_thread = c.thread();

            if (info_class == ThreadWow64Context)
            {
                // ThreadWow64Context is only valid for WOW64 processes
                if (!c.proc.is_wow64_process)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (return_length)
                {
                    return_length.write(sizeof(WOW64_CONTEXT));
                }

                if (thread_information_length < sizeof(WOW64_CONTEXT))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<WOW64_CONTEXT> context_obj{c.emu, thread_information};

                // Check if thread has persistent WOW64 context
                if (!thread->wow64_cpu_reserved.has_value())
                {
                    c.win_emu.log.print(color::red, "Error: WOW64 saved context not initialized for thread %d\n", thread->id);
                    return STATUS_INTERNAL_ERROR;
                }

                // Return the saved context (which was set by NtSetInformationThread)
                thread->wow64_cpu_reserved->access([&](const WOW64_CPURESERVED& ctx) {
                    const auto wow64_context = ctx.Context;
                    context_obj.write(wow64_context);
                });

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadTebInformation)
            {
                if (return_length)
                {
                    return_length.write(sizeof(THREAD_TEB_INFORMATION));
                }

                if (thread_information_length < sizeof(THREAD_TEB_INFORMATION))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const auto teb_info = c.emu.read_memory<THREAD_TEB_INFORMATION>(thread_information);
                const auto data = c.emu.read_memory(thread->teb64->value() + teb_info.TebOffset, teb_info.BytesToRead);
                c.emu.write_memory(teb_info.TebInformation, data.data(), data.size());

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadBasicInformation)
            {
                if (return_length)
                {
                    return_length.write(sizeof(THREAD_BASIC_INFORMATION64));
                }

                if (thread_information_length < sizeof(THREAD_BASIC_INFORMATION64))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<THREAD_BASIC_INFORMATION64> info{c.emu, thread_information};
                info.access([&](THREAD_BASIC_INFORMATION64& i) {
                    i.ExitStatus = thread->exit_status.value_or(STATUS_PENDING);
                    i.TebBaseAddress = thread->teb64->value();
                    i.ClientId = thread->teb64->read().ClientId;
                });

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadAmILastThread)
            {
                if (return_length)
                {
                    return_length.write(sizeof(ULONG));
                }

                if (thread_information_length < sizeof(ULONG))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<ULONG> info{c.emu, thread_information};
                info.write(c.proc.get_live_thread_count() <= 1);

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadQuerySetWin32StartAddress)
            {
                if (return_length)
                {
                    return_length.write(sizeof(EmulatorTraits<Emu64>::PVOID));
                }

                if (thread_information_length < sizeof(EmulatorTraits<Emu64>::PVOID))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<EmulatorTraits<Emu64>::PVOID> info{c.emu, thread_information};
                info.write(thread->start_address);

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadPerformanceCount)
            {
                if (return_length)
                {
                    return_length.write(sizeof(LARGE_INTEGER));
                }

                if (thread_information_length < sizeof(LARGE_INTEGER))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<LARGE_INTEGER> info{c.emu, thread_information};
                info.write({});

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadHideFromDebugger)
            {
                if (thread_information != 0 && thread_information % 4 != 0)
                {
                    return STATUS_DATATYPE_MISALIGNMENT;
                }

                if (thread_information_length != sizeof(BOOLEAN))
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }

                if (return_length)
                {
                    return_length.try_write(sizeof(BOOLEAN));
                }

                const emulator_object<BOOLEAN> info{c.emu, thread_information};
                info.try_write(cur_emulator_thread.debugger_hide);

                c.win_emu.callbacks.on_suspicious_activity("Checking if the thread is hidden from the debugger");

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadTimes)
            {
                if (return_length)
                {
                    return_length.write(sizeof(KERNEL_USER_TIMES));
                }

                if (thread_information_length != sizeof(KERNEL_USER_TIMES))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<KERNEL_USER_TIMES> info{c.emu, thread_information};
                info.write(KERNEL_USER_TIMES{});

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadPriority)
            {
                if (return_length)
                {
                    return_length.write(sizeof(LONG));
                }

                if (thread_information_length < sizeof(LONG))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                constexpr LONG normal_priority = 8;

                const emulator_object<LONG> info{c.emu, thread_information};
                info.write(normal_priority);

                return STATUS_SUCCESS;
            }

            if (info_class == ThreadGroupInformation)
            {
                if (return_length)
                {
                    return_length.write(sizeof(GROUP_AFFINITY));
                }

                if (thread_information_length != sizeof(GROUP_AFFINITY))
                {
                    return STATUS_BUFFER_OVERFLOW;
                }

                const emulator_object<GROUP_AFFINITY> info{c.emu, thread_information};
                info.access([&](GROUP_AFFINITY& ga) {
                    const auto processor_count =
                        c.proc.kusd.access([](const KUSER_SHARED_DATA64& kusd) { return kusd.ActiveProcessorCount; });
                    ga.Mask = processor_count >= 64 ? ~0ull : ((1ull << processor_count) - 1);
                });

                return STATUS_SUCCESS;
            }

            c.win_emu.log.error("Unsupported thread query info class: 0x%X\n", info_class);
            c.emu.stop();

            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS handle_NtOpenThread(const syscall_context& c, const emulator_object<handle> thread_handle, ACCESS_MASK /*desired_access*/,
                                     emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> /*object_attributes*/,
                                     emulator_object<CLIENT_ID64> client_id)
        {
            if (!client_id)
            {
                return STATUS_INVALID_PARAMETER;
            }

            const auto id = client_id.read();

            for (auto& [h_val, t] : c.proc.threads)
            {
                if (t.id == id.UniqueThread)
                {
                    thread_handle.write(c.proc.threads.make_handle(h_val));
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_INVALID_CID;
        }

        NTSTATUS handle_NtOpenThreadToken(const syscall_context& c, const handle thread_handle, const ACCESS_MASK /*desired_access*/,
                                          const BOOLEAN /*open_as_self*/, const emulator_object<handle> token_handle)
        {
            if (!c.proc.is_current_thread_handle(thread_handle, c.vcpu.active_thread))
            {
                return STATUS_NOT_SUPPORTED;
            }

            token_handle.write(CURRENT_THREAD_TOKEN);

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtOpenThreadTokenEx(const syscall_context& c, const handle thread_handle, const ACCESS_MASK desired_access,
                                            const BOOLEAN open_as_self, const ULONG /*handle_attributes*/,
                                            const emulator_object<handle> token_handle)
        {
            return handle_NtOpenThreadToken(c, thread_handle, desired_access, open_as_self, token_handle);
        }

        NTSTATUS handle_NtTerminateThread(const syscall_context& c, const handle thread_handle, const NTSTATUS exit_status)
        {
            auto* thread = !thread_handle.bits ? c.vcpu.active_thread : c.proc.threads.get(thread_handle);

            if (!thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            c.proc.terminate_thread(*thread, exit_status);
            c.win_emu.callbacks.on_thread_terminated(thread_handle, *thread);

            if (thread == c.vcpu.active_thread)
            {
                c.win_emu.yield_thread(c.vcpu);
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtDelayExecution(const syscall_context& c, const BOOLEAN alertable,
                                         const emulator_object<LARGE_INTEGER> delay_interval)
        {
            auto& t = c.thread();
            if (delay_interval.value())
            {
                t.await_time = utils::convert_delay_interval_to_time_point(c.win_emu.clock(), delay_interval.read());
            }
            c.win_emu.yield_thread(c.vcpu, alertable);

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtAlertThreadByThreadId(const syscall_context& c, const uint64_t thread_id)
        {
            for (auto& t : c.proc.threads | std::views::values)
            {
                if (t.id == thread_id)
                {
                    // The alert is sticky: it must be remembered even if the target is not waiting yet, so a
                    // subsequent NtWaitForAlertByThreadId consumes it instead of blocking forever. This race-free
                    // delivery is what ntdll's critical sections and SRW locks rely on.
                    t.alerted = true;
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtAlertThreadByThreadIdEx(const syscall_context& c, const uint64_t thread_id,
                                                  const emulator_object<EMU_RTL_SRWLOCK<EmulatorTraits<Emu64>>> /*lock*/)
        {
            // TODO: Support lock
            /*if (lock.value())
            {
                 c.win_emu.log.warn("NtAlertThreadByThreadIdEx with lock not supported yet!\n");
                //  c.emu.stop();
                //  return STATUS_NOT_SUPPORTED;
            }*/

            return handle_NtAlertThreadByThreadId(c, thread_id);
        }

        NTSTATUS handle_NtWaitForAlertByThreadId(const syscall_context& c, const uint64_t, const emulator_object<LARGE_INTEGER> timeout)
        {
            auto& t = c.thread();

            if (t.alerted)
            {
                // A pending alert was delivered before we started waiting; consume it without blocking.
                t.alerted = false;
                return STATUS_ALERTED;
            }

            t.waiting_for_alert = true;

            if (timeout.value() && !t.await_time.has_value())
            {
                t.await_time = utils::convert_delay_interval_to_time_point(c.win_emu.clock(), timeout.read());
            }

            c.win_emu.yield_thread(c.vcpu);

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtYieldExecution(const syscall_context& c)
        {
            // A child yields because it is waiting on its parent -- and the parent is stopped
            // for as long as this slice runs. End the slice immediately so the parent gets to
            // run and answer; the parent's own yield resumes this child right where it left
            // off. Without this the two sides only ping in one direction and the child gives
            // up after a handful of spins.
            if (c.win_emu.is_child())
            {
                c.win_emu.yield_thread(c.vcpu);
                c.win_emu.stop();
                return STATUS_SUCCESS;
            }

            // Theia's parent busy-waits here while its child works, which makes this the
            // natural place to interleave the two emulated processes: every yield hands each
            // live child another instruction slice. Without it the handshake deadlocks --
            // both sides poll the shared section, so neither can run while the other is
            // stopped.
            if (c.win_emu.has_live_children())
            {
                // Parent spins per child slice. While the child is still booting it needs
                // every slice it can get, but once it has posted a request into the mailbox it
                // only polls -- and it gives up after three polls. The parent's spin is
                // control-flow-flattened, so servicing that request takes it many iterations;
                // at 1:1 the child times out before the parent ever gets there.
                static const uint64_t ratio = [] {
                    const auto* env = getenv("SOGEN_CHILD_YIELD_RATIO");
                    return env ? std::max<uint64_t>(1, strtoull(env, nullptr, 10)) : 1;
                }();

                bool request_pending = false;
                for (auto& [sec_handle, sec] : c.proc.sections)
                {
                    if (!sec.backing_address || !c.win_emu.is_packer_section(sec_handle))
                    {
                        continue;
                    }

                    try
                    {
                        request_pending |= c.emu.read_memory<uint8_t>(sec.backing_address) != 0;
                    }
                    catch (...)
                    {
                    }
                }

                // Once the child has posted, re-arm a watchpoint over the shared view every so
                // often. Each arming catches exactly one parent access and disarms, so this
                // samples what the parent's spin actually touches without permanently
                // trapping every access.
                static const bool watch_section = [] {
                    const auto* enabled = std::getenv("SOGEN_WATCH_SECTION");
                    return enabled && enabled[0] == '1';
                }();

                if (watch_section)
                {
                    // A watch hit reports the mailbox as it was BEFORE the faulting write; this
                    // reports it again afterwards, so the pair brackets the parent's write.
                    for (auto& [watch_base, watch] : c.win_emu.watched_sections_)
                    {
                        if (!watch.report_after)
                        {
                            continue;
                        }

                        watch.report_after = false;

                        std::array<uint8_t, 8> after{};
                        if (c.win_emu.memory.try_read_memory(watch_base, after.data(), after.size()))
                        {
                            c.win_emu.log.print(color::pink, "[WATCH] post=%02x %02x %02x %02x %02x %02x %02x %02x\n", after[0],
                                                after[1], after[2], after[3], after[4], after[5], after[6], after[7]);
                        }
                    }
                }

                // Armed regardless of request_pending: whether the parent touches the mailbox
                // BEFORE the child posts is exactly what says which side is meant to move first.
                if (watch_section)
                {
                    static uint64_t rearm = 0;
                    if ((++rearm % 64) == 0)
                    {
                        for (auto& [sec_handle, sec] : c.proc.sections)
                        {
                            if (sec.backing_address && c.win_emu.is_packer_section(sec_handle))
                            {
                                c.win_emu.arm_section_watch(sec.backing_address,
                                                            static_cast<size_t>(page_align_up(sec.maximum_size)));
                            }
                        }
                    }
                }

                // The parent suspends a worker just before spawning the child and never resumes
                // it. Its spin waits for the mailbox to reach 6 while the child only ever gets
                // it to 2, so something has to make that transition -- the suspended worker is
                // the only candidate. Force it runnable to test that.
                static const bool resume_parent_threads = [] {
                    const auto* enabled = std::getenv("SOGEN_RESUME_PARENT_THREADS");
                    return enabled && enabled[0] == '1';
                }();

                if (resume_parent_threads && request_pending)
                {
                    for (auto& thread : c.proc.threads | std::views::values)
                    {
                        if (thread.suspended > 0 && !thread.is_terminated())
                        {
                            c.win_emu.log.print(color::pink, "[RESUME] parent tid %u suspended=%u -> 0\n", thread.id,
                                                thread.suspended);
                            thread.suspended = 0;
                        }
                    }
                }

                // The parent's cmpxchg waits for the mailbox to read 6 and nothing in our run
                // ever puts it there. Poking that value in makes the exchange succeed, so the
                // protocol can be driven forward one state at a time to see what it expects
                // next. Diagnostic, not a fix.
                static const uint32_t poke_value = [] {
                    const auto* value = std::getenv("SOGEN_POKE_MAILBOX");
                    return value ? static_cast<uint32_t>(strtoul(value, nullptr, 0)) : 0u;
                }();

                // Poking 6 once advanced the protocol a full step: the parent's cmpxchg fired
                // and the child's argument at 0x40 was consumed. So keep supplying it whenever
                // the child has a request outstanding, standing in for whichever participant
                // normally rings that doorbell.
                if (poke_value)
                {
                    static const uint32_t trigger = [] {
                        const auto* value = std::getenv("SOGEN_POKE_WHEN");
                        return value ? static_cast<uint32_t>(strtoul(value, nullptr, 0)) : 2u;
                    }();

                    static uint64_t pokes = 0;
                    for (auto& [sec_handle, sec] : c.proc.sections)
                    {
                        if (!sec.backing_address || !c.win_emu.is_packer_section(sec_handle))
                        {
                            continue;
                        }

                        if (c.emu.read_memory<uint32_t>(sec.backing_address) != trigger)
                        {
                            continue;
                        }

                        c.emu.write_memory<uint32_t>(sec.backing_address, poke_value);

                        if (++pokes <= 40 || (pokes % 500) == 0)
                        {
                            c.win_emu.log.print(color::pink, "[POKE] #%llu mailbox[0] 0x%X -> 0x%X\n",
                                                static_cast<unsigned long long>(pokes), trigger, poke_value);
                        }
                    }
                }

                static uint64_t parent_yields = 0;
                if ((++parent_yields % (request_pending ? ratio : 1)) == 0)
                {
                    // Parent and child never execute at the same time, so sampling the mailbox
                    // either side of the slice attributes every change to one of them. Which
                    // side clears the child's request byte is the whole question.
                    const auto sample = [&c] {
                        std::array<uint8_t, 8> bytes{};
                        for (auto& [sec_handle, sec] : c.proc.sections)
                        {
                            if (!sec.backing_address || !c.win_emu.is_packer_section(sec_handle))
                            {
                                continue;
                            }
                            try
                            {
                                c.emu.read_memory(sec.backing_address, bytes.data(), bytes.size());
                            }
                            catch (...)
                            {
                            }
                        }
                        return bytes;
                    };

                    const auto before = sample();
                    c.win_emu.run_children_slice(CHILD_SLICE_INSTRUCTIONS);
                    const auto after = sample();

                    static std::array<uint8_t, 8> previous_after{};
                    static bool have_previous = false;

                    if (have_previous && previous_after != before)
                    {
                        c.win_emu.log.print(color::pink, "[WROTE] PARENT changed mailbox [0]: %02x -> %02x\n", previous_after[0],
                                            before[0]);
                    }

                    if (before != after)
                    {
                        c.win_emu.log.print(color::pink, "[WROTE] CHILD changed mailbox [0]: %02x -> %02x\n", before[0], after[0]);
                    }

                    previous_after = after;
                    have_previous = true;

                    // The parent never writes to the section across thousands of spins, so the
                    // question is whether its responder thread is simply never runnable.
                    static uint64_t slice_count = 0;
                    if ((++slice_count % 200) == 0)
                    {
                        for (auto& thread : c.proc.threads | std::views::values)
                        {
                            c.win_emu.log.print(color::pink,
                                                "[PTHREAD] tid %u ip=0x%" PRIx64 " terminated=%d suspended=%u awaits=%zu "
                                                "await_time=%d alertable=%d apcs=%zu\n",
                                                thread.id, thread.current_ip, thread.is_terminated() ? 1 : 0, thread.suspended,
                                                thread.await_objects.size(), thread.await_time.has_value() ? 1 : 0,
                                                thread.apc_alertable ? 1 : 0, thread.pending_apcs.size());
                        }
                    }
                }
                static const bool cross_wake = [] {
                    const auto* e = getenv("SOGEN_CROSS_WAKE");
                    return e && e[0] == '1';
                }();
                static const uint64_t cross_wake_delay = [] {
                    const auto* e = getenv("SOGEN_CROSS_WAKE_DELAY");
                    return e ? std::max<uint64_t>(1, strtoull(e, nullptr, 10)) : 1000;
                }();
                if (cross_wake)
                {
                    static uint64_t wake_countdown = 0;
                    if (++wake_countdown >= cross_wake_delay)
                    {
                        for (auto& thread : c.proc.threads | std::views::values)
                        {
                            if (&thread == c.vcpu.active_thread || thread.is_terminated())
                            {
                                continue;
                            }
                            if (thread.suspended == 0 && thread.await_objects.empty())
                            {
                                continue;
                            }

                            bool woke = false;
                            if (thread.suspended > 0)
                            {
                                thread.suspended = 0;
                                woke = true;
                            }
                            for (const auto& obj : thread.await_objects)
                            {
                                if (auto* ev = c.proc.events.get(obj.bits))
                                {
                                    ev->signaled = true;
                                    woke = true;
                                }
                            }

                            if (woke)
                            {
                                c.win_emu.log.print(color::green,
                                                    "[XWAKE] woke parent responder tid %u (suspended->0, signaled %zu awaited)\n",
                                                    thread.id, thread.await_objects.size());
                            }
                        }
                        wake_countdown = 0;
                    }
                }
            }

            static const bool section_responder = [] {
                const auto* e = getenv("SOGEN_SECTION_RESPONDER");
                return e && e[0] == '1';
            }();
            if (section_responder && !c.win_emu.shared_section_backings.empty())
            {
                constexpr uint32_t kMaxResp = 0x1FF000; // data page .. end of a 2 MB section
                for (auto& [sec_handle, sec] : c.proc.sections)
                {
                    if (!sec.backing_address || !c.win_emu.shared_section_backings.contains(sec_handle))
                    {
                        continue;
                    }
                    const auto base = sec.backing_address;

                    uint32_t doorbell = 0;
                    try
                    {
                        doorbell = c.emu.read_memory<uint32_t>(base);
                    }
                    catch (...)
                    {
                        continue;
                    }

                    // 0 = idle, 1 = already answered (awaiting the child's consume). Anything else is a fresh
                    // ring: the child writes 6 for an operation, 2 for the init handshake (FINDINGS 9.53).
                    if (doorbell == 0 || doorbell == 1)
                    {
                        continue;
                    }

                    uint32_t opcode = 0;
                    uint64_t arg0 = 0;
                    uint32_t arg1 = 0;
                    try
                    {
                        opcode = c.emu.read_memory<uint32_t>(base + 0x40);
                        arg0 = c.emu.read_memory<uint64_t>(base + 0x80);
                        arg1 = c.emu.read_memory<uint32_t>(base + 0x88);
                    }
                    catch (...)
                    {
                        continue;
                    }

                    c.win_emu.log.print(color::green,
                                        "[RESPONDER] section %u ring=0x%x opcode=%u arg0=0x%" PRIx64 " arg1=0x%x\n",
                                        static_cast<unsigned>(sec_handle), doorbell, opcode, arg0, arg1);

                    switch (opcode)
                    {
                    case 0: // NtReadVirtualMemory(-1, arg0, buf = section+0x1000, arg1) against the parent
                    {
                        const uint32_t len = std::min<uint32_t>(arg1, kMaxResp);
                        std::vector<uint8_t> buf(len, 0);
                        try
                        {
                            c.emu.read_memory(arg0, buf.data(), buf.size());
                        }
                        catch (...)
                        {
                        }
                        try
                        {
                            c.emu.write_memory(base + 0x1000, buf.data(), buf.size());
                        }
                        catch (...)
                        {
                        }
                        break;
                    }
                    default:
                        break;
                    }

                    try
                    {
                        c.emu.write_memory(base, uint32_t{1});
                    }
                    catch (...)
                    {
                    }
                }
            }

            // One-shot survey of the main image's page protections. Theia marks executable
            // pages PAGE_NOACCESS and decrypts them on an execute fault, so the count of
            // inaccessible pages is the size of the job a page sweep would have.
            {
                static bool surveyed = false;
                if (!surveyed && c.win_emu.mod_manager.executable)
                {
                    surveyed = true;
                    const auto& exe = *c.win_emu.mod_manager.executable;

                    size_t readable = 0;
                    size_t inaccessible = 0;
                    size_t uncommitted = 0;

                    for (uint64_t page = exe.image_base; page < exe.image_base + exe.size_of_image; page += 0x1000)
                    {
                        const auto region = c.win_emu.memory.get_region_info(page);
                        if (!region.is_committed)
                        {
                            ++uncommitted;
                        }
                        else if (region.permissions.common == memory_permission::none)
                        {
                            ++inaccessible;
                        }
                        else
                        {
                            ++readable;
                        }
                    }

                    c.win_emu.log.print(color::pink,
                                        "[PAGESURVEY] %s base=0x%" PRIx64 " size=0x%" PRIx64
                                        " -> readable=%zu inaccessible=%zu uncommitted=%zu\n",
                                        exe.name.c_str(), exe.image_base, exe.size_of_image, readable, inaccessible, uncommitted);
                }
            }

            // Watch the shared mailbox. The child posts a request into the section and polls
            // for the parent's answer, so these bytes are the whole conversation. Dense at
            // first because the handshake plays out within the first few hundred yields, then
            // sparse. Not gated on has_live_children: the state AFTER a child gives up is
            // exactly what says whether the parent ever answered.
            {
                static uint64_t yield_count = 0;
                ++yield_count;

                if (c.win_emu.packer_section_handle && (yield_count <= 400 || (yield_count % 2000) == 0))
                {
                    for (auto& [sec_handle, sec] : c.proc.sections)
                    {
                        if (!sec.backing_address || !c.win_emu.is_packer_section(sec_handle))
                        {
                            continue;
                        }

                        std::array<uint8_t, 16> head{};
                        std::array<uint8_t, 16> at_0x40{};
                        try
                        {
                            c.emu.read_memory(sec.backing_address, head.data(), head.size());
                            c.emu.read_memory(sec.backing_address + 0x40, at_0x40.data(), at_0x40.size());
                        }
                        catch (...)
                        {
                            continue;
                        }

                        static std::array<uint8_t, 16> last_head{};
                        static std::array<uint8_t, 16> last_0x40{};
                        static bool logged_once = false;

                        // Only report when something actually changed, otherwise the parent's
                        // spin buries the log.
                        if (logged_once && head == last_head && at_0x40 == last_0x40)
                        {
                            continue;
                        }

                        last_head = head;
                        last_0x40 = at_0x40;
                        logged_once = true;

                        std::string line{};
                        for (const auto b : head)
                        {
                            line += std::format("{:02x} ", b);
                        }
                        line += " | 0x40: ";
                        for (const auto b : at_0x40)
                        {
                            line += std::format("{:02x} ", b);
                        }

                        c.win_emu.log.print(color::cyan, "[MAILBOX] yield %llu section %u: %s\n",
                                            static_cast<unsigned long long>(yield_count), static_cast<unsigned>(sec_handle),
                                            line.c_str());
                    }
                }
            }

            c.win_emu.yield_thread(c.vcpu);
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtSetThreadExecutionState(const syscall_context& /*c*/, const ULONG /*new_flags*/,
                                                  const emulator_object<ULONG> previous_flags)
        {
            // The emulator never sleeps the system; report the prior continuous state and accept the request.
            constexpr ULONG es_continuous = 0x80000000;
            previous_flags.write_if_valid(es_continuous);
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtSuspendThread(const syscall_context& c, const handle thread_handle,
                                        const emulator_object<ULONG> previous_suspend_count)
        {
            auto* thread = thread_handle == CURRENT_THREAD ? c.vcpu.active_thread : c.proc.threads.get(thread_handle);

            if (!thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            const auto old_count = thread->suspended;
            if (previous_suspend_count)
            {
                previous_suspend_count.write(old_count);
            }

            if (thread->suspended >= 0x7F) // MAXIMUM_SUSPEND_COUNT
            {
                return STATUS_SUSPEND_COUNT_EXCEEDED;
            }

            thread->suspended += 1;

            if (thread == c.vcpu.active_thread)
            {
                c.win_emu.yield_thread(c.vcpu);
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtResumeThread(const syscall_context& c, const handle thread_handle,
                                       const emulator_object<ULONG> previous_suspend_count)
        {
            auto* thread = thread_handle == CURRENT_THREAD ? c.vcpu.active_thread : c.proc.threads.get(thread_handle);
            if (!thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            const auto old_count = thread->suspended;
            if (previous_suspend_count)
            {
                previous_suspend_count.write(old_count);
            }

            if (old_count > 0)
            {
                thread->suspended -= 1;
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtContinueEx(const syscall_context& c, const emulator_object<CONTEXT64> thread_context,
                                     const uint64_t continue_argument)
        {
            c.write_status = false;

            KCONTINUE_ARGUMENT argument{};
            if (continue_argument <= 0xFF)
            {
                argument.ContinueFlags = KCONTINUE_FLAG_TEST_ALERT;
            }
            else
            {
                argument = c.emu.read_memory<KCONTINUE_ARGUMENT>(continue_argument);
            }

            const auto context = thread_context.read();
            cpu_context::restore(c.emu, context);

            if (argument.ContinueFlags & KCONTINUE_FLAG_TEST_ALERT)
            {
                c.win_emu.yield_thread(c.vcpu, true);
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtContinue(const syscall_context& c, const emulator_object<CONTEXT64> thread_context, const BOOLEAN raise_alert)
        {
            return handle_NtContinueEx(c, thread_context, raise_alert ? 1 : 0);
        }

        NTSTATUS handle_NtGetNextThread(const syscall_context& c, const handle process_handle, const handle thread_handle,
                                        const ACCESS_MASK /*desired_access*/, const ULONG /*handle_attributes*/, const ULONG flags,
                                        const emulator_object<handle> new_thread_handle)
        {
            if (!c.proc.is_current_process_handle(process_handle))
            {
                return STATUS_INVALID_HANDLE;
            }

            const auto resolved_thread_handle = c.proc.resolve_object_pseudo_handle(thread_handle, c.vcpu.active_thread);

            if (resolved_thread_handle != NULL_HANDLE && resolved_thread_handle.value.type != handle_types::thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (flags != 0)
            {
                c.win_emu.log.error("NtGetNextThread flags %X not supported\n", static_cast<uint32_t>(flags));
                c.emu.stop();
                return STATUS_NOT_SUPPORTED;
            }

            bool return_next_thread = resolved_thread_handle == NULL_HANDLE;
            for (auto& t : c.proc.threads)
            {
                if (return_next_thread && !t.second.is_terminated())
                {
                    ++t.second.ref_count;
                    new_thread_handle.write(c.proc.threads.make_handle(t.first));
                    return STATUS_SUCCESS;
                }

                if (t.first == resolved_thread_handle.value.id)
                {
                    return_next_thread = true;
                }
            }

            new_thread_handle.write(NULL_HANDLE);
            return STATUS_NO_MORE_ENTRIES;
        }

        NTSTATUS handle_NtGetContextThread(const syscall_context& c, const handle thread_handle,
                                           const emulator_object<CONTEXT64> thread_context)
        {
            const auto* thread = thread_handle == CURRENT_THREAD ? c.vcpu.active_thread : c.proc.threads.get(thread_handle);

            if (!thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            c.vcpu.active_thread->save(c.emu);
            const auto _ = utils::finally([&] {
                c.vcpu.active_thread->restore(c.emu); //
            });

            thread->restore(c.emu);

            thread_context.access([&](CONTEXT64& context) {
                if ((context.ContextFlags & CONTEXT_DEBUG_REGISTERS_64) == CONTEXT_DEBUG_REGISTERS_64)
                {
                    c.win_emu.callbacks.on_suspicious_activity("Reading debug registers");
                }

                cpu_context::save(c.emu, context);
            });

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtSetContextThread(const syscall_context& c, const handle thread_handle,
                                           const emulator_object<CONTEXT64> thread_context)
        {
            const auto* thread = thread_handle == CURRENT_THREAD ? c.vcpu.active_thread : c.proc.threads.get(thread_handle);

            if (!thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            const auto needs_swich = thread != c.vcpu.active_thread;

            if (needs_swich)
            {
                c.vcpu.active_thread->save(c.emu);
                thread->restore(c.emu);
            }

            const auto _ = utils::finally([&] {
                if (needs_swich)
                {
                    c.vcpu.active_thread->restore(c.emu); //
                }
            });

            const auto context = thread_context.read();
            cpu_context::restore(c.emu, context);

            if ((context.ContextFlags & CONTEXT_DEBUG_REGISTERS_64) == CONTEXT_DEBUG_REGISTERS_64)
            {
                c.win_emu.callbacks.on_suspicious_activity("Setting debug registers");
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCreateThreadEx(const syscall_context& c, const emulator_object<handle> thread_handle,
                                         const ACCESS_MASK /*desired_access*/,
                                         const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> /*object_attributes*/,
                                         const handle process_handle, const uint64_t start_routine, const uint64_t argument,
                                         const ULONG create_flags, const EmulatorTraits<Emu64>::SIZE_T /*zero_bits*/,
                                         const EmulatorTraits<Emu64>::SIZE_T stack_size,
                                         const EmulatorTraits<Emu64>::SIZE_T maximum_stack_size,
                                         const emulator_object<PS_ATTRIBUTE_LIST<EmulatorTraits<Emu64>>> attribute_list)
        {
            if (!c.proc.is_current_process_handle(process_handle))
            {
                return STATUS_NOT_SUPPORTED;
            }

            if (maximum_stack_size != 0 && stack_size > maximum_stack_size)
            {
                return STATUS_INVALID_PARAMETER;
            }

            constexpr auto entry_size = sizeof(PS_ATTRIBUTE<EmulatorTraits<Emu64>>);
            constexpr auto header_size = sizeof(PS_ATTRIBUTE_LIST<EmulatorTraits<Emu64>>) - entry_size;

            size_t attribute_count = 0;

            if (attribute_list)
            {
                const auto total_length = attribute_list.read().TotalLength;

                if (total_length < header_size)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                if ((total_length - header_size) % entry_size != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                attribute_count = static_cast<size_t>((total_length - header_size) / entry_size);
            }

            uint64_t actual_stack_size = maximum_stack_size;
            if (actual_stack_size == 0)
            {
                actual_stack_size = c.win_emu.mod_manager.executable->size_of_stack_reserve;
            }

            if (actual_stack_size == 0)
            {
                actual_stack_size = STACK_SIZE;
            }

            actual_stack_size = std::max(stack_size, actual_stack_size);
            actual_stack_size = align_up(actual_stack_size, ALLOCATION_GRANULARITY);

            const auto h = c.proc.create_thread(c.win_emu.memory, start_routine, argument, actual_stack_size, create_flags);

            thread_handle.write(h);

            if (!attribute_list)
            {
                return STATUS_SUCCESS;
            }

            const auto* thread = c.proc.threads.get(h);

            const emulator_object<PS_ATTRIBUTE<EmulatorTraits<Emu64>>> attributes{
                c.emu, attribute_list.value() + offsetof(PS_ATTRIBUTE_LIST<EmulatorTraits<Emu64>>, Attributes)};

            for (size_t i = 0; i < attribute_count; ++i)
            {
                attributes.access(
                    [&](const PS_ATTRIBUTE<EmulatorTraits<Emu64>>& attribute) {
                        const auto type = attribute.Attribute & PS_ATTRIBUTE_NUMBER_MASK;

                        if (type == PsAttributeClientId)
                        {
                            const auto client_id = thread->teb64->read().ClientId;
                            write_attribute(c.emu, attribute, client_id);
                        }
                        else if (type == PsAttributeTebAddress)
                        {
                            write_attribute(c.emu, attribute, thread->teb64->value());
                        }
                        else if (type == PsAttributeGroupAffinity || type == PsAttributeIdealProcessor)
                        {
                            // Scheduling hints; not modeled by the emulator.
                        }
                        else
                        {
                            c.win_emu.log.error("Unsupported thread attribute type: %" PRIx64 "\n", type);
                        }
                    },
                    i);
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtGetCurrentProcessorNumberEx(const syscall_context& c, const emulator_object<PROCESSOR_NUMBER> processor_number)
        {
            PROCESSOR_NUMBER number{};
            number.Number = static_cast<uint8_t>(c.vcpu.cpu.index());
            processor_number.write(number);
            return STATUS_SUCCESS;
        }

        ULONG handle_NtGetCurrentProcessorNumber(const syscall_context& c)
        {
            return static_cast<ULONG>(c.vcpu.cpu.index());
        }

        NTSTATUS handle_NtQueueApcThreadEx2(const syscall_context& c, const handle thread_handle, const handle /*reserve_handle*/,
                                            const uint32_t apc_flags, const uint64_t apc_routine, const uint64_t apc_argument1,
                                            const uint64_t apc_argument2, const uint64_t apc_argument3)
        {
            auto* thread = thread_handle == CURRENT_THREAD ? c.vcpu.active_thread : c.proc.threads.get(thread_handle);

            if (!thread)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (apc_flags)
            {
                c.win_emu.log.warn("Unsupported APC flags: %X\n", apc_flags);
                // c.emu.stop();
                // return STATUS_NOT_SUPPORTED;
            }

            thread->pending_apcs.push_back({
                .flags = apc_flags,
                .apc_routine = apc_routine,
                .apc_argument1 = apc_argument1,
                .apc_argument2 = apc_argument2,
                .apc_argument3 = apc_argument3,
            });

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtQueueApcThreadEx(const syscall_context& c, const handle thread_handle, const handle reserve_handle,
                                           const uint64_t apc_routine, const uint64_t apc_argument1, const uint64_t apc_argument2,
                                           const uint64_t apc_argument3)
        {
            uint32_t flags{0};
            auto real_reserve_handle = reserve_handle;
            if (reserve_handle.bits == QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC)
            {
                real_reserve_handle.bits = 0;
                flags = QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC;
                static_assert(QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC == 1);
            }

            return handle_NtQueueApcThreadEx2(c, thread_handle, real_reserve_handle, flags, apc_routine, apc_argument1, apc_argument2,
                                              apc_argument3);
        }

        NTSTATUS handle_NtQueueApcThread(const syscall_context& c, const handle thread_handle, const uint64_t apc_routine,
                                         const uint64_t apc_argument1, const uint64_t apc_argument2, const uint64_t apc_argument3)
        {
            return handle_NtQueueApcThreadEx(c, thread_handle, make_handle(0), apc_routine, apc_argument1, apc_argument2, apc_argument3);
        }

        NTSTATUS handle_NtCallbackReturn(const syscall_context& c, const emulator_pointer callback_result_ptr,
                                         const ULONG callback_result_length, const NTSTATUS /*callback_status*/)
        {
            auto& t = c.thread();

            if (t.callback_stack.empty())
            {
                throw std::runtime_error("Unexpected callback return");
            }

            user_callback_result callback_result{
                .value = t.callback_return_rax.value_or(c.emu.reg<uint64_t>(x86_register::rax)),
            };
            t.callback_return_rax.reset();

            if (callback_result_ptr != 0 && callback_result_length != 0)
            {
                // When present, the callback result pointer always contains the actual callback result value!
                user_callback_result result_data{};
                const auto read_length = std::min<ULONG>(callback_result_length, sizeof(result_data));
                if (c.win_emu.memory.try_read_memory(callback_result_ptr, &result_data, read_length))
                {
                    callback_result.value = result_data.value;
                    if (callback_result_length >= sizeof(result_data))
                    {
                        callback_result.output_size = result_data.output_size;
                        callback_result.output = result_data.output;
                    }
                }
            }

            auto frame = std::move(t.callback_stack.back());
            t.callback_stack.pop_back();

            frame.restore_registers(c.emu);

            auto dispatch_result =
                c.win_emu.dispatcher.dispatch_completion(c.win_emu, c.vcpu, frame.handler_id, frame.state.get(), callback_result);

            if (dispatch_result == dispatch_result::completed)
            {
                emulator_stack_leak_collector leak_collector{};
                frame.state.reset();
                leak_collector.throw_if_leaked();
            }

            if (dispatch_result != dispatch_result::new_callback)
            {
                // Move past syscall instruction
                const auto new_ip = c.emu.read_instruction_pointer();
                c.emu.reg(x86_register::rip, new_ip + 2);
            }

            c.write_status = false;
            return {};
        }
    }

} // namespace sogen
