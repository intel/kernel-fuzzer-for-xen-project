#ifndef FORKSERVER_H
#define FORKSERVER_H

void afl_setup(void);
void afl_rewind(void);
void afl_wait(void);
void afl_report(bool crash);
void afl_instrument_location(unsigned long cur_loc);

#endif
