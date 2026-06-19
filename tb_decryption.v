`timescale 1ns/1ns

// ============================================================
// USER-CONFIGURABLE PARAMETERS — change these freely.
// Everything else adapts automatically.
// ============================================================
`define k 128
`define r 128
`define a 12
`define b 8
`define l 8    // Length of Associated Data (bits) — any multiple of 8
`define y 160    // Length of Cipher Text / Plain Text (bits) — any multiple of 8
`define v 1

`define KEY   128'h000102030405060708090A0B0C0D0E0F
`define NONCE 128'h101112131415161718191A1B1C1D1E1F
`define AD    144'hab
`define CT    160'hdd44c923badffba33d924cc520578dd57f653cf3

// Update these when inputs change
`define EXPECTED_PT  160'ha1b2c3d4e5f60718293a4b5c6d7e8f9011223344
`define EXPECTED_TAG 128'h0b6e7980cff827826b13aa68a22623ef


module tb_decryption;

    parameter PERIOD = 20;

    reg  clk                  = 0;
    reg  rst                  = 1;
    reg  keyxSI               = 0;
    reg  noncexSI             = 0;
    reg  associated_dataxSI   = 0;
    reg  cipher_textxSI       = 0;
    reg  decryption_startxSI  = 0;

    wire plain_textxSO;
    wire tagxSO;
    wire decryption_readyxSO;

    reg [`y-1:0] plain_text = 0;
    reg [127:0]  tag        = 0;

    // ----------------------------------------------------------------
    // Send registers
    // ----------------------------------------------------------------
    reg [127:0]  key_send   = `KEY;
    reg [127:0]  nonce_send = `NONCE;
    reg [`l-1:0] ad_send    = `AD;
    reg [`y-1:0] ct_send    = `CT;

    // MAX_W: number of serial-load cycles — covers every register
    localparam MAX_W   = (`l >= `y) ? ((`l >= 128) ? `l : 128)
                                    : ((`y >= 128) ? `y : 128);

    // CAPTURE: number of serial-output cycles — covers PT and TAG
    // FIX: use max(y,128) not a hardcoded 128, identical fix as tb_encryption
    localparam CAPTURE = (`y >= 128) ? `y : 128;

    localparam KEY_OFF   = MAX_W - 128;
    localparam NONCE_OFF = MAX_W - 128;
    localparam AD_OFF    = MAX_W - `l;
    localparam CT_OFF    = MAX_W - `y;

    integer i;
    integer start_time;
    integer cycles_taken;

    // DUT
    Ascon_Decryption #(`k, `r, `a, `b, `l, `y, `v) uut (
        .clk                 (clk),
        .rst                 (rst),
        .keyxSI              (keyxSI),
        .noncexSI            (noncexSI),
        .associated_dataxSI  (associated_dataxSI),
        .cipher_textxSI      (cipher_textxSI),
        .decryption_startxSI (decryption_startxSI),
        .plain_textxSO       (plain_textxSO),
        .tagxSO              (tagxSO),
        .decryption_readyxSO (decryption_readyxSO)
    );

    always #(PERIOD/2) clk = ~clk;

    // Block count parameters (mirrors Decryption.v math)
    localparam NZ_AD = ((`l+1) % `r == 0) ? 0 : `r - ((`l+1) % `r);
    localparam L_PAD = `l + 1 + NZ_AD;
    localparam S_BLK = L_PAD / `r;

    localparam NZ_PT = ((`y+1) % `r == 0) ? 0 : `r - ((`y+1) % `r);
    localparam Y_PAD = `y + 1 + NZ_PT;
    localparam T_BLK = Y_PAD / `r;

    integer blk;

    initial begin
        $dumpfile("ascon_dec.vcd");
        $dumpvars;

        $display("============================================");
        $display("    ASCON DECRYPTION FULL VERIFICATION TB  ");
        $display("============================================");
        $display("PARAMETERS: k=%0d r=%0d a=%0d b=%0d l=%0d y=%0d",
                  `k, `r, `a, `b, `l, `y);
        $display("  KEY   : %h", `KEY);
        $display("  NONCE : %h", `NONCE);
        $display("  AD    : %h", `AD);
        $display("  CT    : %h", `CT);
        $display("  AD blocks (s)=%0d  CT blocks (t)=%0d", S_BLK, T_BLK);
        $display("  MAX_W=%0d  KEY_OFF=%0d  NONCE_OFF=%0d  AD_OFF=%0d  CT_OFF=%0d",
                  MAX_W, KEY_OFF, NONCE_OFF, AD_OFF, CT_OFF);
        $display("  CAPTURE=%0d (serial output cycles)", CAPTURE);
        $display("============================================");

        // ============================================================
        // Phase 1: Reset
        // ============================================================
        rst = 1;
        repeat(4) @(posedge clk);

        // ============================================================
        // Phase 2: Serial loading (MSB first, MAX_W cycles)
        // ============================================================
        $display("Phase 2: Serial loading (%0d cycles)...", MAX_W);

        @(negedge clk);
        rst                = 0;
        keyxSI             = (MAX_W-1 >= KEY_OFF)   ? key_send  [MAX_W-1 - KEY_OFF]   : 1'b0;
        noncexSI           = (MAX_W-1 >= NONCE_OFF) ? nonce_send[MAX_W-1 - NONCE_OFF] : 1'b0;
        associated_dataxSI = (MAX_W-1 >= AD_OFF)    ? ad_send   [MAX_W-1 - AD_OFF]    : 1'b0;
        cipher_textxSI     = (MAX_W-1 >= CT_OFF)    ? ct_send   [MAX_W-1 - CT_OFF]    : 1'b0;

        for (i = MAX_W-2; i >= 0; i = i - 1) begin
            @(negedge clk);
            keyxSI             = (i >= KEY_OFF)   ? key_send  [i - KEY_OFF]   : 1'b0;
            noncexSI           = (i >= NONCE_OFF) ? nonce_send[i - NONCE_OFF] : 1'b0;
            associated_dataxSI = (i >= AD_OFF)    ? ad_send   [i - AD_OFF]    : 1'b0;
            cipher_textxSI     = (i >= CT_OFF)    ? ct_send   [i - CT_OFF]    : 1'b0;
        end

        @(negedge clk);
        keyxSI = 0; noncexSI = 0; associated_dataxSI = 0; cipher_textxSI = 0;
        repeat(2) @(posedge clk);

        // ============================================================
        // Verify serial load
        // ============================================================
        $display("--------------------------------------------");
        $display("LOADED VALUES:");
        $display("  key   : %h  %s", uut.key,
                  (uut.key             == `KEY)   ? "MATCH" : "MISMATCH");
        $display("  nonce : %h  %s", uut.nonce,
                  (uut.nonce           == `NONCE) ? "MATCH" : "MISMATCH");
        $display("  AD    : %h  %s", uut.associated_data,
                  (uut.associated_data == `AD)    ? "MATCH" : "MISMATCH");
        $display("  CT    : %h  %s", uut.cipher_text,
                  (uut.cipher_text     == `CT)    ? "MATCH" : "MISMATCH");
        $display("  i=%0d ready=%b", uut.i, uut.ready);
        $display("--------------------------------------------");
        $display("Initial state S = IV||K||N (before p12):");
        $display("  S0=%h", uut.decryption_core.S[319:256]);
        $display("  S1=%h", uut.decryption_core.S[255:192]);
        $display("  S2=%h", uut.decryption_core.S[191:128]);
        $display("  S3=%h", uut.decryption_core.S[127:64]);
        $display("  S4=%h", uut.decryption_core.S[63:0]);
        $display("--------------------------------------------");

        if (uut.key !== `KEY || uut.nonce !== `NONCE ||
            uut.associated_data !== `AD || uut.cipher_text !== `CT) begin
            $display("ERROR: Serial loading mismatch. Aborting.");
            $finish;
        end

        // ============================================================
        // Phase 3: Start decryption
        // ============================================================
        @(negedge clk);
        decryption_startxSI = 1;
        start_time = $time;
        repeat(2) @(posedge clk);
        @(negedge clk);
        decryption_startxSI = 0;
        $display("Phase 3: Decryption started.");

        // ============================================================
        // INITIALIZATION p12
        // ============================================================
        $display("--------------------------------------------");
        $display("INITIALIZATION p12 (%0d rounds):", `a);
        wait(uut.decryption_core.state == 1);

        @(posedge clk);
        $display("  [loaded]: x0=%h x1=%h x2=%h x3=%h x4=%h",
            uut.decryption_core.p1.x0_q, uut.decryption_core.p1.x1_q,
            uut.decryption_core.p1.x2_q, uut.decryption_core.p1.x3_q,
            uut.decryption_core.p1.x4_q);
        repeat(`a) begin
            @(posedge clk);
            $display("  round   : x0=%h x1=%h x2=%h x3=%h x4=%h",
                uut.decryption_core.p1.x0_q, uut.decryption_core.p1.x1_q,
                uut.decryption_core.p1.x2_q, uut.decryption_core.p1.x3_q,
                uut.decryption_core.p1.x4_q);
        end

        wait(uut.decryption_core.state != 1);
        @(posedge clk);
        $display("--------------------------------------------");
        $display("State after p12 + key XOR:");
        $display("  S0=%h", uut.decryption_core.S[319:256]);
        $display("  S1=%h", uut.decryption_core.S[255:192]);
        $display("  S2=%h", uut.decryption_core.S[191:128]);
        $display("  S3=%h", uut.decryption_core.S[127:64]);
        $display("  S4=%h", uut.decryption_core.S[63:0]);
        $display("--------------------------------------------");

        // ============================================================
        // ASSOCIATED DATA (skipped if l==0)
        // ============================================================
        if (S_BLK > 0) begin
            $display("============================================");
            $display("  AD ABSORPTION (%0d block(s))", S_BLK);
            $display("============================================");

            for (blk = 0; blk < S_BLK; blk = blk + 1) begin
                wait(uut.decryption_core.state == 2 &&
                     uut.decryption_core.block_ctr == blk);
                @(posedge clk);
                $display("  AD block %0d P_in: x0=%h x1=%h",
                    blk,
                    uut.decryption_core.P_in[319:256],
                    uut.decryption_core.P_in[255:192]);
                $display("             state x2=%h x3=%h x4=%h",
                    uut.decryption_core.P_in[191:128],
                    uut.decryption_core.P_in[127:64],
                    uut.decryption_core.P_in[63:0]);

                @(posedge uut.decryption_core.p1.done);
                @(posedge clk);
                $display("  AD block %0d done. S0=%h S1=%h",
                    blk,
                    uut.decryption_core.S[319:256],
                    uut.decryption_core.S[255:192]);
            end
        end

        // ============================================================
        // State after AD + domain separation
        // ============================================================
        wait(uut.decryption_core.state == 3);
        @(posedge clk);
        $display("--------------------------------------------");
        $display("State after AD + domain sep:");
        $display("  S0=%h", uut.decryption_core.S[319:256]);
        $display("  S1=%h", uut.decryption_core.S[255:192]);
        $display("  S2=%h", uut.decryption_core.S[191:128]);
        $display("  S3=%h", uut.decryption_core.S[127:64]);
        $display("  S4=%h", uut.decryption_core.S[63:0]);
        $display("--------------------------------------------");

        // ============================================================
        // CT/PT PROCESSING (skipped if y==0)
        // ============================================================
        if (T_BLK > 0) begin
            $display("============================================");
            $display("  CT/PT PROCESSING (%0d block(s))", T_BLK);
            $display("============================================");

            for (blk = 0; blk < T_BLK; blk = blk + 1) begin
                wait(uut.decryption_core.state == 3 &&
                     uut.decryption_core.block_ctr == blk);
                @(posedge clk);
                $display("  CT block %0d P_in:  x0=%h x1=%h",
                    blk,
                    uut.decryption_core.P_in[319:256],
                    uut.decryption_core.P_in[255:192]);
                $display("  CT block %0d P_d :  %h",
                    blk,
                    uut.decryption_core.P_d);

                if (blk < T_BLK - 1) begin
                    @(posedge uut.decryption_core.p1.done);
                    @(posedge clk);
                    $display("  CT block %0d done. S0=%h", blk, uut.decryption_core.S[319:256]);
                end
            end
        end

        // ============================================================
        // FINALIZE
        // ============================================================
        $display("--------------------------------------------");
        $display("Entering FINALIZE. S before key XOR:");
        wait(uut.decryption_core.state == 4);
        @(posedge clk);
        $display("  S0=%h", uut.decryption_core.S[319:256]);
        $display("  S1=%h", uut.decryption_core.S[255:192]);
        $display("  S2=%h", uut.decryption_core.S[191:128]);
        $display("  S3=%h", uut.decryption_core.S[127:64]);
        $display("  S4=%h", uut.decryption_core.S[63:0]);
        $display("  P_in (S^key): x0=%h x1=%h x2=%h x3=%h x4=%h",
            uut.decryption_core.P_in[319:256],
            uut.decryption_core.P_in[255:192],
            uut.decryption_core.P_in[191:128],
            uut.decryption_core.P_in[127:64],
            uut.decryption_core.P_in[63:0]);

        $display("--------------------------------------------");
        $display("FINALIZE p12 (%0d rounds):", `a);
        @(posedge clk);
        $display("  [loaded]: x0=%h x1=%h x2=%h x3=%h x4=%h",
            uut.decryption_core.p1.x0_q, uut.decryption_core.p1.x1_q,
            uut.decryption_core.p1.x2_q, uut.decryption_core.p1.x3_q,
            uut.decryption_core.p1.x4_q);
        repeat(`a) begin
            @(posedge clk);
            $display("  round   : x0=%h x1=%h x2=%h x3=%h x4=%h",
                uut.decryption_core.p1.x0_q, uut.decryption_core.p1.x1_q,
                uut.decryption_core.p1.x2_q, uut.decryption_core.p1.x3_q,
                uut.decryption_core.p1.x4_q);
        end

        $display("--------------------------------------------");
        $display("P_out after finalize p12:");
        $display("  P_out[319:256]=%h", uut.decryption_core.P_out[319:256]);
        $display("  P_out[255:192]=%h", uut.decryption_core.P_out[255:192]);
        $display("  P_out[191:128]=%h", uut.decryption_core.P_out[191:128]);
        $display("  P_out[127:64] =%h", uut.decryption_core.P_out[127:64]);
        $display("  P_out[63:0]   =%h", uut.decryption_core.P_out[63:0]);
        $display("  Tag_d (comb)  =%h", uut.decryption_core.Tag_d);
        $display("  P (raw PT)    =%h", uut.decryption_core.P);
        @(posedge clk);
        $display("  Tag (latched) =%h", uut.decryption_core.Tag);
        $display("--------------------------------------------");

        // ============================================================
        // Phase 4: Wait for decryption_ready
        // ============================================================
        begin : wait_ready
            integer timeout;
            timeout = 0;
            while (!decryption_readyxSO && timeout < 2000) begin
                @(posedge clk);
                timeout = timeout + 1;
            end
            if (timeout >= 2000) begin
                $display("TIMEOUT waiting for decryption_ready");
                $finish;
            end
        end

        cycles_taken = ($time - start_time) / PERIOD;
        $display("Phase 4: Decryption complete in %0d cycles.", cycles_taken);

        // ============================================================
        // Phase 5: Capture serial output — CAPTURE cycles, LSB first.
        //
        // FIX: loop runs CAPTURE = max(y,128) times, not hardcoded 128.
        // Each signal independently gated so we never read past its width:
        //   y <  128 → loop runs 128 times; PT gated at y,  TAG full
        //   y == 128 → both run 128 bits
        //   y >  128 → loop runs y times;   PT full,        TAG gated at 128
        // ============================================================
        @(posedge clk);
        plain_text[0] = plain_textxSO;
        tag[0]        = tagxSO;

        for (i = 1; i < CAPTURE; i = i + 1) begin
            @(posedge clk);
            if (i < `y)  plain_text[i] = plain_textxSO;
            if (i < 128) tag[i]        = tagxSO;
        end

        // ============================================================
        // Results
        // ============================================================
        $display("============================================");
        $display("              RESULTS");
        $display("============================================");
        $display("  Cycles  : %0d", cycles_taken);
        $display("  GOT PT  : %h", plain_text);
        $display("  EXP PT  : %h  %s", `EXPECTED_PT,
                  (plain_text == `EXPECTED_PT) ? "PASS" : "FAIL");
        $display("  GOT TAG : %h", tag);
        $display("  EXP TAG : %h  %s", `EXPECTED_TAG,
                  (tag == `EXPECTED_TAG) ? "PASS" : "FAIL");
        $display("============================================");
        $finish;
    end

endmodule