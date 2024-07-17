analyze -sv riscv_crypto_fu_saes64_taint.v

elaborate -top riscv_crypto_fu_saes64

clock g_clk
reset g_resetn -non_resettable_regs 0


# check once the computation is finsihed that there is no 
# information leak to the registar where data is stored
assume {rs1_t == 0 && valid-t == 0}
assert {rd_t == 0}


# Set the time limit to 1 hour (3600 seconds)
set_prove_time_limit 3600
prove -all