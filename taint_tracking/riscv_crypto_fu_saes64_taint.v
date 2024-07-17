// 
// Copyright (C) 2020 
//    SCARV Project  <info@scarv.org>
//    Ben Marshall   <ben.marshall@bristol.ac.uk>
// 
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
// IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

//
// module: riscv_crypto_fu_saes64
//
//  Implements the scalar 64-bit AES instructions for the RISC-V
//  cryptography extension
//
//  The following table shows which instructions are implemented
//  based on the selected value of XLEN, and the feature enable
//  parameter name(s).
//
//  Instruction     | XLEN=32 | XLEN=64 | Feature Parameter 
//  ----------------|---------|---------|----------------------------------
//   saes64.ks1     |         |    x    |
//   saes64.ks2     |         |    x    |
//   saes64.imix    |         |    x    | SAES_DEC_EN
//   saes64.encs    |         |    x    |
//   saes64.encsm   |         |    x    |
//   saes64.decs    |         |    x    | SAES_DEC_EN
//   saes64.decsm   |         |    x    | SAES_DEC_EN
//

`include "riscv_crypto_fu_sboxes_taint.v"
`include "riscv_crypto_fu_aes_mix_columns_taint.v"

module riscv_crypto_fu_saes64 #(
parameter SAES_DEC_EN = 1 , // Enable the saes64 decrypt instructions.
parameter SAES64_SBOXES = 8   // saes64 sbox instances. Valid values: 8,4
)(

input  wire         g_clk           , // Global clock
input  wire         g_resetn        , // Synchronous active low reset.

input  wire         valid           , // Are the inputs valid?
input  wire [ 63:0] rs1             , // Source register 1
input  wire [ 63:0] rs2             , // Source register 2
input  wire [  3:0] enc_rcon        , // rcon immediate for ks1 instruction

input  wire         op_saes64_ks1   , // RV64 AES Encrypt KeySchedule 1
input  wire         op_saes64_ks2   , // RV64 AES Encrypt KeySchedule 2
input  wire         op_saes64_imix  , // RV64 AES Decrypt KeySchedule Mix
input  wire         op_saes64_encs  , // RV64 AES Encrypt SBox
input  wire         op_saes64_encsm , // RV64 AES Encrypt SBox + MixCols
input  wire         op_saes64_decs  , // RV64 AES Decrypt SBox
input  wire         op_saes64_decsm , // RV64 AES Decrypt SBox + MixCols

output wire [ 63:0] rd              , // output destination register value.
output wire         ready           ,             // Compute finished?

// -----Taint Signals-----
input  wire valid_t           , 
input  wire rs1_t             , 
input  wire rs2_t             ,
input  wire enc_rcon_t        , 

input  wire op_saes64_ks1_t   , 
input  wire op_saes64_ks2_t  , 
input  wire op_saes64_imix_t  , 
input  wire op_saes64_encs_t  , 
input  wire op_saes64_encsm_t , 
input  wire op_saes64_decs_t  ,
input  wire op_saes64_decsm_t ,

output wire  rd_t              ,
output wire  ready_t             

);

// ---- Taint Logic ----

function OR_t;
    input op1;
    input op2;
    input op1_t;
    input op2_t;

    OR_t = (~op1 & op2_t) | (~op2 & op1_t) | (op1_t & op2_t);
endfunction

function AND_t;
    input op1;
    input op2;
    input op1_t;
    input op2_t;

    AND_t = (op1_t & op2_t) | (op1_t & ~op2_t & op2) | (~op1_t & op2_t & op1);
endfunction


// Select I'th byte of X.
`define BY(X,I) X[7+8*I:8*I]

// Always finish in a single cycle.
assign     ready            = valid && sbox_ready;

assign      ready_t         = AND_t(valid, sbox_ready, valid_t, sbox_ready_t);

// AES Round Constants
wire [ 7:0] rcon [0:15];
assign rcon[ 0] = 8'h01; assign rcon[ 8] = 8'h1b;
assign rcon[ 1] = 8'h02; assign rcon[ 9] = 8'h36;
assign rcon[ 2] = 8'h04; assign rcon[10] = 8'h00;
assign rcon[ 3] = 8'h08; assign rcon[11] = 8'h00;
assign rcon[ 4] = 8'h10; assign rcon[12] = 8'h00;
assign rcon[ 5] = 8'h20; assign rcon[13] = 8'h00;
assign rcon[ 6] = 8'h40; assign rcon[14] = 8'h00;
assign rcon[ 7] = 8'h80; assign rcon[15] = 8'h00;

// AES Round Constants taint values
wire [ 7:0] rcon_t [0:15];
assign rcon_t[ 0] = 8'h00; assign rcon_t[ 8] = 8'h00;
assign rcon_t[ 1] = 8'h00; assign rcon_t[ 9] = 8'h00;
assign rcon_t[ 2] = 8'h00; assign rcon_t[10] = 8'h00;
assign rcon_t[ 3] = 8'h00; assign rcon_t[11] = 8'h00;
assign rcon_t[ 4] = 8'h00; assign rcon_t[12] = 8'h00;
assign rcon_t[ 5] = 8'h00; assign rcon_t[13] = 8'h00;
assign rcon_t[ 6] = 8'h00; assign rcon_t[14] = 8'h00;
assign rcon_t[ 7] = 8'h00; assign rcon_t[15] = 8'h00;

//
// Shift Rows
// ------------------------------------------------------------

wire [31:0] row_0   = {`BY(rs1,0),`BY(rs1,4),`BY(rs2,0),`BY(rs2,4)};
wire [31:0] row_1   = {`BY(rs1,1),`BY(rs1,5),`BY(rs2,1),`BY(rs2,5)};
wire [31:0] row_2   = {`BY(rs1,2),`BY(rs1,6),`BY(rs2,2),`BY(rs2,6)};
wire [31:0] row_3   = {`BY(rs1,3),`BY(rs1,7),`BY(rs2,3),`BY(rs2,7)};

// Shift Rows Taint
// ------------------------------------------------------------------

wire row_0_t = rs1_t || rs2_t;
wire row_1_t = rs1_t || rs2_t;
wire row_2_t = rs1_t || rs2_t;
wire row_3_t = rs1_t || rs2_t;

// Forward shift rows
wire [31:0] fsh_0   =  row_0;                      
wire [31:0] fsh_1   = {row_1[23: 0], row_1[31:24]};
wire [31:0] fsh_2   = {row_2[15: 0], row_2[31:16]};
wire [31:0] fsh_3   = {row_3[ 7: 0], row_3[31: 8]};

// Forward shift rows taint
wire [31:0] fsh_0_t   =  row_0_t  ;                    
wire [31:0] fsh_1_t   = row_1_t;
wire [31:0] fsh_2_t   = row_2_t;
wire [31:0] fsh_3_t   = row_3_t;

// Inverse shift rows
wire [31:0] ish_0   =  row_0;
wire [31:0] ish_1   = {row_1[ 7: 0], row_1[31: 8]};
wire [31:0] ish_2   = {row_2[15: 0], row_2[31:16]};
wire [31:0] ish_3   = {row_3[23: 0], row_3[31:24]};

// Inverse shift rows taint
wire [31:0] ish_0_t  =  row_0_t;
wire [31:0] ish_1_t   = row_1_t;
wire [31:0] ish_2_t  = row_2_t;
wire [31:0] ish_3_t   = row_3_t;

//
// Re-construct columns from rows
wire [31:0] f_col_1 = {`BY(fsh_3,2),`BY(fsh_2,2),`BY(fsh_1,2),`BY(fsh_0,2)};
wire [31:0] f_col_0 = {`BY(fsh_3,3),`BY(fsh_2,3),`BY(fsh_1,3),`BY(fsh_0,3)};

wire [31:0] i_col_1 = {`BY(ish_3,2),`BY(ish_2,2),`BY(ish_1,2),`BY(ish_0,2)};
wire [31:0] i_col_0 = {`BY(ish_3,3),`BY(ish_2,3),`BY(ish_1,3),`BY(ish_0,3)};

//

// Re-construct columns from rows taint
wire f_col_1_t = fsh_3_t || fsh_2_t || fsh_1_t || fsh_0_t;
wire f_col_0_t = fsh_3_t || fsh_2_t || fsh_1_t || fsh_0_t;

wire i_col_1_t = ish_3_t || ish_2_t || ish_1_t || ish_0_t;
wire i_col_0_t = ish_3_t || ish_2_t || ish_1_t || ish_0_t;

// Hi/Lo selection

wire [63:0] shiftrows_enc = {f_col_1, f_col_0};
wire [63:0] shiftrows_dec = {i_col_1, i_col_0};

// Hi/Lo selection taints

wire shiftrows_enc_t = f_col_1_t || f_col_0_t;
wire shiftrows_dec_t = i_col_1_t || i_col_0_t;

//
// SubBytes
// ------------------------------------------------------------

//
// SBox input/output
wire [ 7:0] sb_fwd_in  [7:0];
wire [ 7:0] sb_fwd_out [7:0];
wire [ 7:0] sb_inv_in  [7:0];
wire [ 7:0] sb_inv_out [7:0];

// SBox input/output taints
wire sb_fwd_in_t;
wire sb_fwd_out_t;
wire sb_inv_in_t;
wire sb_inv_out_t;


wire        sbox_ready      ;
wire        sbox_ready_t    ;

//
// KeySchedule 1 SBox input selection
wire        rcon_rot    = enc_rcon != 4'hA;
wire [ 7:0] rconst      = rcon_rot ? rcon[enc_rcon] : 8'b0;

wire [ 7:0] ks1_sb3     = rcon_rot ? rs1[39:32] : rs1[63:56];
wire [ 7:0] ks1_sb2     = rcon_rot ? rs1[63:56] : rs1[55:48];
wire [ 7:0] ks1_sb1     = rcon_rot ? rs1[55:48] : rs1[47:40];
wire [ 7:0] ks1_sb0     = rcon_rot ? rs1[47:40] : rs1[39:32];

wire [31:0] ks1_sbout   = e_sbout[31:0] ^ {24'b0, rconst};


// KeySchedule 1 SBOX input selection taint
wire rcon_rot_t = enc_rcon_t; //ask about optimization with this given its a boolean value
wire rconst_t = rcon_rot_t || rcon_t[enc_rcon];
wire ks1_sb3_t = rcon_rot_t || rs1_t;
wire ks1_sb2_t = rcon_rot_t || rs1_t;
wire ks1_sb1_t = rcon_rot_t || rs1_t;
wire ks1_sb0_t = rcon_rot_t || rs1_t;

wire ks1_sbout_t = e_sbout_t || rconst_t;

// If just doing sub-bytes, sbox inputs direct from rs1.
assign      sb_fwd_in[0]= op_saes64_ks1 ? ks1_sb0 : `BY(shiftrows_enc, 0);
assign      sb_fwd_in[1]= op_saes64_ks1 ? ks1_sb1 : `BY(shiftrows_enc, 1);
assign      sb_fwd_in[2]= op_saes64_ks1 ? ks1_sb2 : `BY(shiftrows_enc, 2);
assign      sb_fwd_in[3]= op_saes64_ks1 ? ks1_sb3 : `BY(shiftrows_enc, 3);
assign      sb_fwd_in[4]=                           `BY(shiftrows_enc, 4);
assign      sb_fwd_in[5]=                           `BY(shiftrows_enc, 5);
assign      sb_fwd_in[6]=                           `BY(shiftrows_enc, 6);
assign      sb_fwd_in[7]=                           `BY(shiftrows_enc, 7);

assign      sb_inv_in[0]= `BY(shiftrows_dec, 0);
assign      sb_inv_in[1]= `BY(shiftrows_dec, 1);
assign      sb_inv_in[2]= `BY(shiftrows_dec, 2);
assign      sb_inv_in[3]= `BY(shiftrows_dec, 3);
assign      sb_inv_in[4]= `BY(shiftrows_dec, 4);
assign      sb_inv_in[5]= `BY(shiftrows_dec, 5);
assign      sb_inv_in[6]= `BY(shiftrows_dec, 6);
assign      sb_inv_in[7]= `BY(shiftrows_dec, 7);

// taint variation of sbox inouts direct from rs1
assign      sb_fwd_in_t = (op_saes64_ks1_t ? ks1_sb0_t : shiftrows_enc_t) || (op_saes64_ks1_t && (ks1_sb0_t != shiftrows_enc_t));
assign      sb_inv_in_t = shiftrows_dec_t;

// Decrypt sbox output
wire [63:0] d_sbout     = {
    sb_inv_out[7], sb_inv_out[6], sb_inv_out[5], sb_inv_out[4],
    sb_inv_out[3], sb_inv_out[2], sb_inv_out[1], sb_inv_out[0] 
};

// Decrypt sbox output taint
wire d_sbout_t = sb_inv_out_t;

// Encrypt sbox output
wire [63:0] e_sbout     = {
    sb_fwd_out[7], sb_fwd_out[6], sb_fwd_out[5], sb_fwd_out[4],
    sb_fwd_out[3], sb_fwd_out[2], sb_fwd_out[1], sb_fwd_out[0] 
};

// Encrypt sbox output taint
wire e_sbout_t = sb_fwd_out_t;

//
// MixColumns
// ------------------------------------------------------------

// Forward MixColumns inputs.
wire [31:0] mix_enc_i0  =                               e_sbout[31: 0];
wire [31:0] mix_enc_i1  =                               e_sbout[63:32];

// Forward MixColumns input taints.
wire mix_enc_i0_t = e_sbout_t;
wire mix_enc_i1_t = e_sbout_t;


// Inverse MixColumns inputs.
wire [31:0] mix_dec_i0  = op_saes64_imix ? rs1[31: 0] : d_sbout[31: 0];
wire [31:0] mix_dec_i1  = op_saes64_imix ? rs1[63:32] : d_sbout[63:32];

// Inverse MixColumns input taints.
wire mix_dec_i0_t = (op_saes64_imix_t ? rs1_t : d_sbout_t) || (op_saes64_imix_t && (rs1_t != d_sbout_t));
wire mix_dec_i1_t = (op_saes64_imix_t ? rs1_t : d_sbout_t) || (op_saes64_imix_t && (rs1_t != d_sbout_t));

// Forward MixColumns outputs.
wire [31:0] mix_enc_o0  ;
wire [31:0] mix_enc_o1  ;

// Inverse MixColumns outputs.
wire [31:0] mix_dec_o0  ;
wire [31:0] mix_dec_o1  ;


//
// Result gathering
// ------------------------------------------------------------

wire [63:0] result_ks1  = {ks1_sbout, ks1_sbout};

wire [63:0] result_ks2  = {
    rs1[63:32] ^ rs2[63:32] ^ rs2[31:0] ,
    rs1[63:32] ^ rs2[31: 0]
};


wire        mix         = op_saes64_encsm || op_saes64_decsm        ;

wire [63:0] result_enc  = mix ? {mix_enc_o1, mix_enc_o0} : e_sbout  ;

wire [63:0] result_dec  = mix ? {mix_dec_o1, mix_dec_o0} : d_sbout  ;

wire [63:0] result_imix =       {mix_dec_o1, mix_dec_o0}            ;

wire        op_enc      = op_saes64_encs || op_saes64_encsm;
wire        op_dec      = op_saes64_decs || op_saes64_decsm;

assign rd = 
    {64{op_saes64_ks1          }} & result_ks1     |
    {64{op_saes64_ks2          }} & result_ks2     |
    {64{op_enc                 }} & result_enc     |
    {64{op_dec                 }} & result_dec     |
    {64{op_saes64_imix         }} & result_imix    ;

// Result gathering taints
// ------------------------------------------------------------
    wire result_ks1_t = ks1_sbout_t;
    wire result_ks2_t = rs1_t || rs2_t;
    wire mix_t = OR_t(op_saes64_encsm, op_saes64_decsm, op_saes64_encsm_t, op_saes64_decsm_t);
    wire result_enc_t = (mix_t || e_sbout_t);
    wire result_dec_t = (mix_t || d_sbout_t);

    wire op_enc_t = OR_t(op_saes64_encs, op_saes64_encsm, op_saes64_encs_t, op_saes64_encsm_t);
    wire op_dec_t = OR_t(op_saes64_decs, op_saes64_decsm, op_saes64_decs_t, op_saes64_decsm_t);

// Used for rd_t
    wire x = op_saes64_ks1 & result_ks1;
    wire x_t = AND_t(op_saes64_ks1, result_ks1, op_saes64_ks1_t, result_ks1_t);
    wire y = op_saes64_ks2 & result_ks2;
    wire y_t = AND_t(op_saes64_ks2, result_ks2, op_saes64_ks2_t, result_ks2_t);
    wire a = op_enc & result_enc;
    wire a_t = AND_t(op_enc, result_enc, op_enc_t, result_enc_t);
    wire b = op_dec & result_dec;
    wire b_t = AND_t(op_dec, result_dec, op_dec_t, result_dec_t);
    wire c = op_saes64_imix & result_imix;
    wire c_t = op_saes64_imix_t;

    assign rd_t = OR_t(x,y,x_t,y_t) || OR_t(a,b,a_t,b_t) || c_t;
// -------------------------------------------------------------------
//
// Generate AES SBox instances
// ------------------------------------------------------------

genvar i;

generate if(SAES64_SBOXES == 8) begin : saes64_8_sboxes
    
    // All sboxes complete in a single cycle.
    assign sbox_ready = 1'b1;

    for(i = 0; i < 8; i = i + 1) begin

        riscv_crypto_aes_fwd_sbox i_fwd_sbox (
            .in(sb_fwd_in [i]),
            .in_t(sb_fwd_in_t),
            .fx(sb_fwd_out[i]),
            .fx_t(sb_fwd_out_t)
        );

        if(SAES_DEC_EN) begin : saes64_dec_sboxes_implemented

            riscv_crypto_aes_inv_sbox i_inv_sbox (
                .in(sb_inv_in [i]),
                .in_t(sb_inv_in_t),
                .fx(sb_inv_out[i]),
                .fx_t(sb_inv_out_t)

            );

        end else begin  : saes64_dec_sboxes_not_implemented

            assign sb_inv_out[i] = 8'b0;
            assign sb_inv_out_t = 0; //question if this is the right approach

        end

    end

end else if(SAES64_SBOXES == 4) begin : saes64_4_sboxes

    // Is this an instruction using >4 sboxes?
    wire sbox_instr = op_saes64_encs || op_saes64_encsm ||
                      op_saes64_decs || op_saes64_decsm ||
                      op_saes64_ks1  ;
    wire sbox_instr_t = OR_t(op_saes64_encs, op_saes64_encsm, op_saes64_encs_t, op_saes64_encsm_t) || 
                        OR_t(op_saes64_decs, op_saes64_decsm, op_saes64_decs_t, op_saes64_decsm_t) ||
                        op_saes64_ks1_t;

    reg sbox_hi;
    reg sbox_hi_t;

    reg [7:0]   sbox_regs [3:0];
    wire[7:0] n_sbox_inv  [3:0];
    wire[7:0] n_sbox_fwd  [3:0];

    wire      sbox_reg_ld_en = !sbox_hi && sbox_instr && valid;
    wire      sbox_reg_ld_en_t = AND_t(sbox_instr, valid, sbox_instr_t, valid_t);

    assign sbox_ready = sbox_hi && sbox_instr || !sbox_instr;
    assign sbox_ready_t = sbox_instr_t;

    reg sbox_regs_t;

    for(i = 0; i < 4; i = i + 1) begin

        always @(posedge g_clk) begin
            if(sbox_reg_ld_en) begin
                if(op_dec) begin
                    sbox_regs[i] <= n_sbox_inv[i];
                    sbox_regs_t <= sbox_reg_ld_en_t || op_dec_t;
                end else begin
                    sbox_regs[i] <= n_sbox_fwd[i];
                    sbox_regs_t <= sbox_reg_ld_en_t || op_dec_t;
                end
            end
        end

        assign sb_inv_out[i  ] = sbox_regs [i  ];
        assign sb_inv_out[i+4] = n_sbox_inv[i  ];
        assign sb_fwd_out[i  ] = sbox_regs [i  ];
        assign sb_fwd_out[i+4] = n_sbox_fwd[i  ];

        assign sb_inv_out_t = sbox_regs_t;
        assign sb_fwd_out_t = sbox_regs_t;
        
        riscv_crypto_aes_fwd_sbox i_fwd_sbox (
            .in(sb_fwd_in [i + (sbox_hi ? 4 : 0)]),
            .in_t(sb_fwd_in_t),
            .fx(n_sbox_fwd[i                    ]),
            .fx(0)
        );

        if(SAES_DEC_EN) begin : saes64_dec_sboxes_implemented

            riscv_crypto_aes_inv_sbox i_inv_sbox (
                .in(sb_inv_in [i + (sbox_hi ? 4 : 0)]),
                .in_t(sb_inv_in_t),
                .fx(n_sbox_inv[i                    ]),
                .fx_t(0)
            );

        end else begin  : saes64_dec_sboxes_not_implemented

            assign n_sbox_inv[i] = 8'b0;

        end

    end

    always @(posedge g_clk) begin
        if(!g_resetn) begin
            sbox_hi <= 1'b0;
        end else if(valid && ready) begin
            sbox_hi <= 1'b0;
            sbox_hi_t <= AND_t(valid, ready, valid_t, ready_t);
        end else if(valid && sbox_instr) begin
            sbox_hi <= 1'b1;
            sbox_hi_t <= AND_t(valid, sbox_instr, valid_t, sbox_instr_t);
        end
    end

end endgenerate

//
// Mix Column Instances
//
//  These take an entire column word, and output the 32-bit result of the
//  (Inv)MixColumns function
//
// ------------------------------------------------------------

riscv_crypto_aes_mixcolumn_enc i_mix_e0(
    .col_in (mix_enc_i0),
    .col_out(mix_enc_o0)
);
riscv_crypto_aes_mixcolumn_enc i_mix_e1(
    .col_in (mix_enc_i1),
    .col_out(mix_enc_o1)
);

generate if(SAES_DEC_EN) begin : saes64_dec_mix_columns_implemented

riscv_crypto_aes_mixcolumn_dec i_mix_d0(
    .col_in (mix_dec_i0),
    .col_out(mix_dec_o0)
);
riscv_crypto_aes_mixcolumn_dec i_mix_d1(
    .col_in (mix_dec_i1),
    .col_out(mix_dec_o1)
);

end else begin : saes64_dec_mix_columns_implemented

assign mix_dec_o0 = 32'b0;
assign mix_dec_o1 = 32'b0;

end endgenerate

`undef BY

endmodule

