#ifndef BUILD_H
#define BUILD_H

// RELEASE_MODE:   remove debug modules for generate template
// PIC_MODE:       run unit tests under runtime PIC instance
// NOT_CAMOUFLAGE: disable all modules about camouflage for debug

// #define RELEASE_MODE
#define PIC_MODE
// #define NOT_CAMOUFLAGE

#ifdef PIC_MODE
    #define RELEASE_MODE
#endif // PIC_MODE

// disable special warnings for RELEASE_MODE
#ifdef RELEASE_MODE
    #pragma warning(disable: 4206)
#endif

#endif // BUILD_H
