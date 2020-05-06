#ifndef FORKSERVER_H
#define FORKSERVER_H

void afl_setup(void);
void afl_wait(void);
void afl_report(bool crash);
void afl_dummy_instrument(void);
void afl_instrument_location(unsigned long cur_loc);
void afl_get_input(void);

#endif
