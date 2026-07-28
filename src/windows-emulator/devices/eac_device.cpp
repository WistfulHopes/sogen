#include "../std_include.hpp"
#include "eac_device.hpp"

#include "../windows_emulator.hpp"

namespace sogen
{
    namespace
    {
        // Theia (ZeroItLab) refuses to initialise unless it can talk to the EasyAntiCheat
        // driver: it opens \Device\EasyAntiCheat_EOS and issues a small set of ioctls. With
        // no device present it reports an error and tears down, which under emulation shows
        // up as a MessageBeep + a #32770 dialog and then a crash in Theia's error path.
        //
        // Emulating the device here is far cleaner than the native alternative (a signed
        // kernel driver + test signing), and it is fully under our control.
        //
        // Codes and replies are from the reversingthread.info Theia write-up, and IOCTL
        // 0x226013 is independently confirmed against MTFS by our own instrumented driver.
        constexpr ULONG IOCTL_EAC_UNK0 = 0x226003;
        constexpr ULONG IOCTL_EAC_UNK1 = 0x226013;
        constexpr ULONG IOCTL_EAC_UNK2 = 0x22E017;

        struct eac_device : io_device
        {
            // 0x226013 answers 4 on the first call and 1 on every call after it.
            bool first_unk1_call{true};

            void create(windows_emulator&, const io_device_creation_data&) override
            {
            }

            void serialize_object(utils::buffer_serializer& buffer) const override
            {
                buffer.write(this->first_unk1_call);
            }

            void deserialize_object(utils::buffer_deserializer& buffer) override
            {
                buffer.read(this->first_unk1_call);
            }

            NTSTATUS io_control(windows_emulator& win_emu, const io_device_context& c) override
            {
                const auto reply = [&](const std::array<uint8_t, 4>& data) -> NTSTATUS {
                    if (!c.output_buffer || c.output_buffer_length < data.size())
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    win_emu.emu().write_memory(c.output_buffer, data.data(), data.size());

                    if (c.io_status_block)
                    {
                        IO_STATUS_BLOCK<EmulatorTraits<Emu64>> block{};
                        block.Information = data.size();
                        c.io_status_block.write(block);
                    }

                    return STATUS_SUCCESS;
                };

                switch (c.io_control_code)
                {
                case IOCTL_EAC_UNK0:
                    win_emu.log.print(color::cyan, "[EAC] ioctl 0x226003 -> 19 04 00 00\n");
                    return reply({0x19, 0x04, 0x00, 0x00});

                case IOCTL_EAC_UNK1: {
                    const std::array<uint8_t, 4> data =
                        this->first_unk1_call ? std::array<uint8_t, 4>{0x04, 0x00, 0x00, 0x00} //
                                              : std::array<uint8_t, 4>{0x01, 0x00, 0x00, 0x00};
                    win_emu.log.print(color::cyan, "[EAC] ioctl 0x226013 (%s) -> %02x 00 00 00\n",
                                      this->first_unk1_call ? "first" : "subsequent", data[0]);
                    this->first_unk1_call = false;
                    return reply(data);
                }

                case IOCTL_EAC_UNK2:
                    win_emu.log.print(color::cyan, "[EAC] ioctl 0x22e017 -> STATUS_SUCCESS\n");
                    return STATUS_SUCCESS;

                default:
                    // Succeed unknown codes rather than failing: MTFS ships a 2026 Theia
                    // against a 2024 write-up, so it may ask for more than these three.
                    // Log them -- an unexpected code here is exactly what we want to see.
                    win_emu.log.print(color::yellow, "[EAC] UNKNOWN ioctl 0x%X (in %u bytes, out %u bytes) -> STATUS_SUCCESS\n",
                                      c.io_control_code, c.input_buffer_length, c.output_buffer_length);
                    return STATUS_SUCCESS;
                }
            }
        };
    }

    std::unique_ptr<io_device> create_eac_device(const device_creation_context&)
    {
        return std::make_unique<eac_device>();
    }

} // namespace sogen
