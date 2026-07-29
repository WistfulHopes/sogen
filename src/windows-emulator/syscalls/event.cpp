#include "../emulator_utils.hpp"
#include "../syscall_utils.hpp"

namespace sogen
{

    namespace syscalls
    {
        NTSTATUS handle_NtSetEvent(const syscall_context& c, const uint64_t handle, const emulator_object<LONG> previous_state)
        {
            if (handle == DBWIN_DATA_READY)
            {
                if (c.proc.dbwin_buffer && c.win_emu.callbacks.on_debug_string)
                {
                    constexpr auto pid_length = 4;
                    const auto debug_data = read_string<char>(c.win_emu.memory, c.proc.dbwin_buffer + pid_length);
                    c.win_emu.callbacks.on_debug_string(debug_data);
                }

                return STATUS_SUCCESS;
            }

            auto* entry = c.proc.events.get(handle);
            if (!entry)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (previous_state.value())
            {
                previous_state.write(entry->signaled ? 1ULL : 0ULL);
            }

            entry->signaled = true;
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtPulseEvent(const syscall_context& c, const uint64_t handle, const emulator_object<LONG> previous_state)
        {
            auto* entry = c.proc.events.get(handle);
            if (!entry)
            {
                return STATUS_INVALID_HANDLE;
            }

            if (previous_state.value())
            {
                previous_state.write(entry->signaled ? 1ULL : 0ULL);
            }

            // Pulse: momentarily signal the event so threads already blocked on it wake, then return it to
            // the non-signaled state. Threads that are not currently waiting miss the pulse, matching the
            // lossy NtPulseEvent semantics. The cooperative scheduler only re-evaluates readiness at context
            // switches, so wake the current waiters explicitly while the event is signaled.
            entry->signaled = true;

            const auto event_handle = make_handle(handle);
            for (auto& thread : c.proc.threads | std::views::values)
            {
                if (std::ranges::find(thread.await_objects, event_handle) != thread.await_objects.end())
                {
                    (void)thread.is_thread_ready(c.win_emu);
                }
            }

            entry->signaled = false;
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtTraceEvent()
        {
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtQueryEvent(const syscall_context& c, const handle event_handle, const uint32_t event_information_class,
                                     const emulator_object<EVENT_BASIC_INFORMATION> event_information,
                                     const uint32_t event_information_length, const emulator_object<uint32_t> return_length)
        {
            if (event_information_class != 0) // EventBasicInformation
            {
                return STATUS_INVALID_INFO_CLASS;
            }

            if (event_information_length < sizeof(EVENT_BASIC_INFORMATION))
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            EVENT_TYPE type = NotificationEvent;
            bool is_signaled = false;

            if (auto* entry = c.proc.events.get(event_handle))
            {
                type = entry->type;
                is_signaled = entry->signaled;
            }

            event_information.access([&](EVENT_BASIC_INFORMATION& info) {
                info.EventType = type;
                info.EventState = is_signaled ? 1 : 0;
            });

            if (return_length)
            {
                return_length.write(sizeof(EVENT_BASIC_INFORMATION));
            }

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtClearEvent(const syscall_context& c, const handle event_handle)
        {
            auto* e = c.proc.events.get(event_handle);
            if (!e)
            {
                return STATUS_INVALID_HANDLE;
            }

            e->signaled = false;
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtCreateEvent(const syscall_context& c, const emulator_object<handle> event_handle,
                                      const ACCESS_MASK /*desired_access*/,
                                      const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                      const EVENT_TYPE event_type, const BOOLEAN initial_state)
        {
            std::u16string name{};
            if (object_attributes)
            {
                const auto attributes = object_attributes.read();
                if (attributes.ObjectName)
                {
                    name = read_unicode_string(c.emu, attributes.ObjectName);
                    c.win_emu.callbacks.on_generic_access("Opening event", name);
                }
            }

            if (!name.empty())
            {
                for (auto& entry : c.proc.events)
                {
                    if (entry.second.name == name)
                    {
                        ++entry.second.ref_count;
                        event_handle.write(c.proc.events.make_handle(entry.first));
                        return STATUS_OBJECT_NAME_EXISTS;
                    }
                }
            }

            event e{};
            e.type = event_type;
            e.signaled = initial_state != FALSE;
            e.name = std::move(name);

            const auto handle = c.proc.events.store(std::move(e));
            event_handle.write(handle);

            static_assert(sizeof(EVENT_TYPE) == sizeof(uint32_t));
            static_assert(sizeof(ACCESS_MASK) == sizeof(uint32_t));

            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtOpenEvent(const syscall_context& c, const emulator_object<uint64_t> event_handle,
                                    const ACCESS_MASK /*desired_access*/,
                                    const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes)
        {
            const auto attributes = object_attributes.read();
            const auto name = read_unicode_string(c.emu, attributes.ObjectName);
            c.win_emu.callbacks.on_generic_access("Opening event", name);

            if (name == u"\\KernelObjects\\SystemErrorPortReady")
            {
                event_handle.write(WER_PORT_READY.bits);
                return STATUS_SUCCESS;
            }

            if (name == u"Global\\SvcctrlStartEvent_A3752DX")
            {
                event_handle.write(SVCCTRL_START_EVENT.bits);
                return STATUS_SUCCESS;
            }

            if (name == u"\\SECURITY\\LSA_AUTHENTICATION_INITIALIZED")
            {
                event_handle.write(LSA_AUTHENTICATION_INITIALIZED.bits);
                return STATUS_SUCCESS;
            }

            if (name == u"DBWIN_DATA_READY")
            {
                event_handle.write(DBWIN_DATA_READY.bits);
                return STATUS_SUCCESS;
            }

            if (name == u"DBWIN_BUFFER_READY")
            {
                event_handle.write(DBWIN_BUFFER_READY.bits);
                return STATUS_SUCCESS;
            }

            for (auto& entry : c.proc.events)
            {
                if (entry.second.name == name)
                {
                    ++entry.second.ref_count;
                    event_handle.write(c.proc.events.make_handle(entry.first).bits);
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_NOT_FOUND;
        }
        
        template <typename Store>
        void collect_wait32_candidate_event(Store& store, const uint32_t id, std::optional<handle>& resolved, uint32_t& candidate_count)
        {
            if (!store.get_by_index(id))
            {
                return;
            }

            ++candidate_count;
            if (!resolved)
            {
                resolved = store.make_handle(id);
            }
        }

        std::optional<handle> resolve_wait32_handle_event(const syscall_context& c, const uint32_t raw_handle)
        {
            const auto decoded = make_handle(static_cast<uint64_t>(raw_handle));
            if (decoded.value.type != handle_types::reserved)
            {
                return decoded;
            }

            // wait32 can give raw 32 bit handles without type bits
            const auto id = static_cast<uint32_t>(decoded.value.id);
            if (id == 0)
            {
                return std::nullopt;
            }

            std::optional<handle> resolved{};
            uint32_t candidate_count = 0;

            collect_wait32_candidate_event(c.proc.events, id, resolved, candidate_count);
            collect_wait32_candidate_event(c.proc.threads, id, resolved, candidate_count);
            collect_wait32_candidate_event(c.proc.mutants, id, resolved, candidate_count);
            collect_wait32_candidate_event(c.proc.semaphores, id, resolved, candidate_count);
            collect_wait32_candidate_event(c.proc.ports, id, resolved, candidate_count);
            collect_wait32_candidate_event(c.proc.io_completions, id, resolved, candidate_count);
            collect_wait32_candidate_event(c.proc.timers, id, resolved, candidate_count);

            if (candidate_count == 1)
            {
                return resolved;
            }

            return std::nullopt;
        }

        handle resolve_wait_handle_event(const syscall_context& c, const handle h)
        {
            const auto resolved = c.proc.resolve_object_pseudo_handle(h, c.vcpu.active_thread);
            if (resolved.value.type != handle_types::reserved || resolved.value.is_pseudo)
            {
                return resolved;
            }

            if (const auto recovered = resolve_wait32_handle_event(c, static_cast<uint32_t>(resolved.bits)))
            {
                return *recovered;
            }

            return resolved;
        }

        NTSTATUS validate_wait_handle_event(const syscall_context& c, const handle h)
        {
            const auto validate_handle_in_store = [&](auto& store) -> NTSTATUS {
                return store.get(h) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
            };

            switch (h.value.type)
            {
            case handle_types::process:
                // The synthetic Steam process never signals, so a liveness wait times out ("alive").
                return (h == GUEST_PROCESS_HANDLE || h == STEAM_PROCESS_HANDLE) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;

            case handle_types::file:
                if (h.value.is_pseudo)
                {
                    return STATUS_SUCCESS;
                }

                return validate_handle_in_store(c.proc.files);

            case handle_types::event:
                if (h.value.is_pseudo)
                {
                    return STATUS_SUCCESS;
                }

                return validate_handle_in_store(c.proc.events);

            case handle_types::thread:
                return validate_handle_in_store(c.proc.threads);

            case handle_types::mutant:
                return validate_handle_in_store(c.proc.mutants);

            case handle_types::semaphore:
                return validate_handle_in_store(c.proc.semaphores);

            case handle_types::port:
                return validate_handle_in_store(c.proc.ports);

            case handle_types::io_completion:
                return validate_handle_in_store(c.proc.io_completions);

            case handle_types::timer:
                if (h.value.is_pseudo)
                {
                    return STATUS_SUCCESS;
                }

                return validate_handle_in_store(c.proc.timers);

            case handle_types::reserved:
                return STATUS_INVALID_HANDLE;

            default:
                c.win_emu.log.error("Wait handle type not supported: %u (raw 0x%llx, pseudo=%u, id=%u)\n", static_cast<uint32_t>(h.value.type), static_cast<unsigned long long>(h.bits), static_cast<uint32_t>(h.value.is_pseudo), static_cast<uint32_t>(h.value.id));
                return STATUS_INVALID_HANDLE;
            }
        }

        NTSTATUS validate_keyed_event_handle(const syscall_context& c, const handle h)
        {
            const auto resolved = resolve_wait_handle_event(c, h);

            if (c.proc.keyed_events.get(resolved) ||
                (resolved.value.type == handle_types::event && resolved.value.is_pseudo))
            {
                return STATUS_SUCCESS;
            }

            // Resolves to a live object of some other type: right handle, wrong kind of object.
            if (NT_SUCCESS(validate_wait_handle_event(c, resolved)))
            {
                return STATUS_OBJECT_TYPE_MISMATCH;
            }

            return STATUS_INVALID_HANDLE;
        }

        NTSTATUS handle_NtCreateKeyedEvent(const syscall_context& c, const emulator_object<handle> keyed_event_handle,
                                           const ACCESS_MASK /*desired_access*/,
                                           const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes,
                                           const ULONG /*flags*/)
        {
            std::u16string name{};
            if (object_attributes)
            {
                const auto attributes = object_attributes.read();
                if (attributes.ObjectName)
                {
                    name = read_unicode_string(c.emu, attributes.ObjectName);
                    c.win_emu.callbacks.on_generic_access("Opening keyed event", name);
                }
            }

            if (!name.empty())
            {
                for (auto& entry : c.proc.timers)
                {
                    if (entry.second.name == name)
                    {
                        ++entry.second.ref_count;
                        keyed_event_handle.write(c.proc.timers.make_handle(entry.first));
                        return STATUS_OBJECT_NAME_EXISTS;
                    }
                }
            }

            auto handle = c.proc.keyed_events.store({keyed_event{}});
            keyed_event_handle.write(handle);
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtOpenKeyedEvent(const syscall_context& c, const emulator_object<uint64_t> keyed_event_handle,
                                         const ACCESS_MASK /*desired_access*/,
                                         const emulator_object<OBJECT_ATTRIBUTES<EmulatorTraits<Emu64>>> object_attributes)
        {
            const auto attributes = object_attributes.read();
            const auto name = read_unicode_string(c.emu, attributes.ObjectName);
            c.win_emu.callbacks.on_generic_access("Opening event", name);

            if (name == u"\\KernelObjects\\SystemErrorPortReady")
            {
                keyed_event_handle.write(WER_PORT_READY.bits);
                return STATUS_SUCCESS;
            }

            if (name == u"Global\\SvcctrlStartEvent_A3752DX")
            {
                keyed_event_handle.write(SVCCTRL_START_EVENT.bits);
                return STATUS_SUCCESS;
            }

            if (name == u"\\SECURITY\\LSA_AUTHENTICATION_INITIALIZED")
            {
                keyed_event_handle.write(LSA_AUTHENTICATION_INITIALIZED.bits);
                return STATUS_SUCCESS;
            }

            if (name == u"DBWIN_DATA_READY")
            {
                keyed_event_handle.write(DBWIN_DATA_READY.bits);
                return STATUS_SUCCESS;
            }

            if (name == u"DBWIN_BUFFER_READY")
            {
                keyed_event_handle.write(DBWIN_BUFFER_READY.bits);
                return STATUS_SUCCESS;
            }

            for (auto& entry : c.proc.keyed_events)
            {
                if (entry.second.name == name)
                {
                    keyed_event_handle.write(entry.first);
                    return STATUS_SUCCESS;
                }
            }

            return STATUS_NOT_FOUND;
        }

        NTSTATUS handle_NtReleaseKeyedEvent(const syscall_context& c, const uint64_t keyed_event_handle, const uint64_t key,
                                            const BOOLEAN alertable, const emulator_object<LARGE_INTEGER> /*timeout*/)
        {
            if (key & 1)
            {
                return STATUS_INVALID_PARAMETER_1;
            }

            const auto type_status = validate_keyed_event_handle(c, make_handle(keyed_event_handle));
            if (!NT_SUCCESS(type_status))
            {
                return type_status;
            }

            auto entry = c.proc.keyed_events.get(make_handle(keyed_event_handle));
            if (!entry)
            {
                // A pseudo keyed event: accepted as the right object type, but there is no store entry to
                // signal on.
                return STATUS_INVALID_HANDLE;
            }

            if (entry->signaled.contains(key))
            {
                entry->signaled[key] = entry->signaled[key] ? 1ULL : 0ULL;
            }

            entry->signaled[key] = true;
            c.vcpu.thread().apc_alertable = alertable;
            return STATUS_SUCCESS;
        }

        NTSTATUS handle_NtWaitForKeyedEvent(const syscall_context& c, const uint64_t keyed_event_handle, const uint64_t key,
                                            const BOOLEAN alertable, const emulator_object<LARGE_INTEGER> timeout)
        {
            if (key & 1)
            {
                return STATUS_INVALID_PARAMETER_1;
            }

            std::optional<LARGE_INTEGER> timeout_value{};
            if (timeout.value())
            {
                timeout_value = timeout.try_read();
                if (!timeout_value.has_value())
                {
                    return STATUS_ACCESS_VIOLATION;
                }
            }

            const auto type_status = validate_keyed_event_handle(c, make_handle(keyed_event_handle));
            if (!NT_SUCCESS(type_status))
            {
                return type_status;
            }

            const auto resolved_handle = resolve_wait_handle_event(c, make_handle(keyed_event_handle));
            const auto validation_status = validate_wait_handle_event(c, resolved_handle);
            if (!NT_SUCCESS(validation_status))
            {
                return validation_status;
            }

            auto& t = c.thread();
            t.await_objects = {resolved_handle};
            t.await_any = false;
            t.await_key = key;

            if (timeout_value.has_value() && !t.await_time.has_value())
            {
                t.await_time = utils::convert_delay_interval_to_time_point(c.win_emu.clock(), *timeout_value);
            }

            c.win_emu.yield_thread(c.vcpu, alertable);
            return STATUS_SUCCESS;
        }
    }

} // namespace sogen
