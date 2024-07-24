analyze -sva selfcomp_aes64.v

elaborate -top SAES64_Tester

clock g_clk
reset g_resetn -non_resettable_regs 0
stopat rd1
stopat rd2
assume {rd1 == rd2}
assert {oneReady -> bothReady}
assert {bothReady -> rd1 == rd2}

set_prove_time_limit 3600
prove -bg -all

set_engine_mode Tri