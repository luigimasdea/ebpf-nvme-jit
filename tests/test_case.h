#include "ebpf.h"

struct ebpf_inst test_prog[] = {
    { 183, 0, 0, 0, 42 },
    { 150, 0, 0, 0, 0 },
    { 183, 0, 0, 0, 43 },
    { 149, 0, 0, 0, 0 },
};
