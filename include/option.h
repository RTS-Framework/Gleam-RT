#ifndef OPTION_H
#define OPTION_H

// about runtime options at the template tail.
//
// +------------+---------+---------+---------+---------+
// | magic mark | xor key | option1 | option2 | optionN |
// +------------+---------+---------+---------+---------+
// |    0xFC    | 32 byte |   var   |   var   |   var   |
// +------------+---------+---------+---------+---------+

#define OPTION_STUB_MAGIC 0xFC
#define OPTION_STUB_SIZE  128
#define OPTION_KEY_SIZE   32

#define OPT_OFFSET_BASE                  (1 + OPTION_KEY_SIZE)
#define OPT_OFFSET_IMAGE_PINNING_HASH    (OPT_OFFSET_BASE + 0)
#define OPT_OFFSET_SHIELD_MODULE_HASH    (OPT_OFFSET_BASE + 8)
#define OPT_OFFSET_SHIELD_ENTRY_POINT    (OPT_OFFSET_BASE + 16)
#define OPT_OFFSET_SHIELD_MEM_ADDRESS    (OPT_OFFSET_BASE + 24)
#define OPT_OFFSET_ENABLE_SECURITY_MODE  (OPT_OFFSET_BASE + 32)
#define OPT_OFFSET_DISABLE_DETECTOR      (OPT_OFFSET_BASE + 33)
#define OPT_OFFSET_DISABLE_WATCHDOG      (OPT_OFFSET_BASE + 34)
#define OPT_OFFSET_DISABLE_SYSMON        (OPT_OFFSET_BASE + 35)
#define OPT_OFFSET_NOT_ERASE_INSTRUCTION (OPT_OFFSET_BASE + 36)
#define OPT_OFFSET_NOT_ADJUST_PROTECT    (OPT_OFFSET_BASE + 37)
#define OPT_OFFSET_TRACK_CURRENT_THREAD  (OPT_OFFSET_BASE + 38)

// reserve stub for store runtime options.
#pragma warning(push)
#pragma warning(disable: 4276)
extern void Option_Stub();
#pragma warning(pop)

#endif // OPTION_H
