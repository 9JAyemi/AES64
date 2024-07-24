// -------------------------------------------------------------
//Module for testing self composition for AES64 implementation
//--------------------------------------------------------------

`include "riscv_crypto_fu_saes64.v"

module SAES64_Tester (
input g_clk, // Global clock
input  g_resetn, // Synchronous active low reset.
input   valid, // Are the inputs valid?
input  [ 63:0] rs1,
input  [ 63:0] rs1_copy, // Source register 1
input   [ 63:0] rs2, // Source register 2
input   [  3:0] enc_rcon, // rcon immediate for ks1 instruction
input op_saes64_ks1, // RV64 AES Encrypt KeySchedule 1
input  op_saes64_ks2, // RV64 AES Encrypt KeySchedule 2
input  op_saes64_imix, // RV64 AES Decrypt KeySchedule Mix
input  op_saes64_encs, // RV64 AES Encrypt SBox
input  op_saes64_encsm, // RV64 AES Encrypt SBox + MixCols
input  op_saes64_decs, // RV64 AES Decrypt SBox
input  op_saes64_decsm  // RV64 AES Decrypt SBox + MixCols

          // output destination register value.
);

// Internal Wires
wire readyOne;
wire readyTwo;
wire [ 63:0] rd1;
wire [63:0]  rd2;  

riscv_crypto_fu_saes64 num1(
    .g_clk(g_clk),
    .g_resetn(g_resetn),
    .valid(valid),
    .rs1(rs1),
    .rs2(rs1_copy),
    .enc_rcon(enc_rcon),
     .op_saes64_ks1(op_saes64_ks1),
    .op_saes64_ks2(op_saes64_ks2),
    .op_saes64_imix(op_saes64_imix),
    .op_saes64_encs(op_saes64_encs),
    .op_saes64_encsm(op_seas64_encsm),
    .op_saes64_decs(op_seas64_decs),
    .op_saes64_decsm(op_saes64_decsm),
    .rd(rd1),
    .ready(readyOne)
);

riscv_crypto_fu_saes64 num2(
    .g_clk(g_clk),
    .g_resetn(g_resetn),
    .valid(valid),
    .rs1(rs1),
    .rs2(rs2),
    .enc_rcon(enc_rcon),
    .op_saes64_ks1(op_saes64_ks1),
    .op_saes64_ks2(op_saes64_ks2),
    .op_saes64_imix(op_saes64_imix),
    .op_saes64_encs(op_saes64_encs),
    .op_saes64_encsm(op_seas64_encsm),
    .op_saes64_decs(op_seas64_decs),
    .op_saes64_decsm(op_saes64_decsm),
    .rd(rd2),
    .ready(readyTwo)
);

assign oneReady = readyOne || readyTwo;
assign bothReady = readyOne & readyTwo;

endmodule
