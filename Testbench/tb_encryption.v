`timescale 1ns/1ns

// ============================================================
// USER-CONFIGURABLE PARAMETERS — change these freely.
// Everything else adapts automatically.
// ============================================================
`define k 128          // Key size (bits)
`define r 128          // Rate (bits)
`define a 12           // Init / finalize rounds
`define b 8            // AD / PT permutation rounds
`define l 172          // Associated Data length (bits)  ← any multiple of 8
`define y 8          // Plaintext length (bits)        ← any multiple of 8
`define v 1            // AEAD variant

`define KEY   128'h000102030405060708090A0B0C0D0E0F
`define NONCE 128'h101112131415161718191A1B1C1D1E1F
`define AD    172'h303132333435363738393A3B3C3D3E3F40414243444
`define PT    8'h20

// Expected outputs (update when you change inputs)
`define EXPECTED_CT  8'hCC
`define EXPECTED_TAG 128'hBA9027A1FA8400FF1BCFBD744F1A803E

module tb_encryption;

    parameter PERIOD = 20;

    // ----------------------------------------------------------------
    // DUT ports
    // ----------------------------------------------------------------
    reg  clk                  = 0;
    reg  rst                  = 1;
    reg  keyxSI               = 0;
    reg  noncexSI             = 0;
    reg  associated_dataxSI   = 0;
    reg  plain_textxSI        = 0;
    reg  encryption_startxSI  = 0;

    wire cipher_textxSO;
    wire tagxSO;
    wire encryption_readyxSO;

    // ----------------------------------------------------------------
    // Output capture registers
    // ----------------------------------------------------------------
    reg [`y-1:0] cipher_text = 0;
    reg [127:0]  tag         = 0;

    // ----------------------------------------------------------------
    // Send shift registers (sized to their exact widths)
    // ----------------------------------------------------------------
    reg [127:0]  key_send   = `KEY;
    reg [127:0]  nonce_send = `NONCE;
    reg [`l-1:0] ad_send    = `AD;
    reg [`y-1:0] pt_send    = `PT;

    // ----------------------------------------------------------------
    // MAX_W: number of serial-load cycles (must cover every register)
    // CAPTURE: number of serial-output cycles (must cover CT and TAG)
    // Both are computed purely from parameters — no magic constants.
    // ----------------------------------------------------------------
    localparam MAX_W   = (`l  >= `y)   ? ((`l  >= 128) ? `l  : 128)
                                       : ((`y  >= 128) ? `y  : 128);
    localparam CAPTURE = (`y  >= 128)  ? `y : 128;  // enough for CT and TAG

    // Per-signal MSB-alignment offsets inside the MAX_W-wide shift window
    localparam KEY_OFF   = MAX_W - 128;
    localparam NONCE_OFF = MAX_W - 128;
    localparam AD_OFF    = MAX_W - `l;
    localparam PT_OFF    = MAX_W - `y;

    integer i;
    integer start_time;
    integer cycles_taken;

    // ----------------------------------------------------------------
    // DUT instantiation
    // ----------------------------------------------------------------
    Ascon_Encryption #(`k, `r, `a, `b, `l, `y, `v) uut (
        .clk                 (clk),
        .rst                 (rst),
        .keyxSI              (keyxSI),
        .noncexSI            (noncexSI),
        .associated_dataxSI  (associated_dataxSI),
        .plain_textxSI       (plain_textxSI),
        .encryption_startxSI (encryption_startxSI),
        .cipher_textxSO      (cipher_textxSO),
        .tagxSO              (tagxSO),
        .encryption_readyxSO (encryption_readyxSO)
    );

    always #(PERIOD/2) clk = ~clk;

    // ----------------------------------------------------------------
    // Block count parameters (mirrors Encryption.v math exactly)
    // ----------------------------------------------------------------
    localparam NZ_AD = ((`l+1) % `r == 0) ? 0 : `r - ((`l+1) % `r);
    localparam L_PAD = `l + 1 + NZ_AD;
    localparam S_BLK = L_PAD / `r;

    localparam NZ_PT = ((`y+1) % `r == 0) ? 0 : `r - ((`y+1) % `r);
    localparam Y_PAD = `y + 1 + NZ_PT;
    localparam T_BLK = Y_PAD / `r;

    integer blk;

    initial begin
        $dumpfile("ascon_enc.vcd");
        $dumpvars;

        $display("============================================");
        $display("    ASCON WRAPPER FULL VERIFICATION TB     ");
        $display("============================================");
        $display("PARAMETERS: k=%0d r=%0d a=%0d b=%0d l=%0d y=%0d",
                  `k, `r, `a, `b, `l, `y);
        $display("  KEY   : %h", `KEY);
        $display("  NONCE : %h", `NONCE);
        $display("  AD    : %h", `AD);
        $display("  PT    : %h", `PT);
        $display("  AD blocks (s)=%0d  PT blocks (t)=%0d", S_BLK, T_BLK);
        $display("  MAX_W=%0d  KEY_OFF=%0d  NONCE_OFF=%0d  AD_OFF=%0d  PT_OFF=%0d",
                  MAX_W, KEY_OFF, NONCE_OFF, AD_OFF, PT_OFF);
        $display("  CAPTURE=%0d (serial output cycles)", CAPTURE);
        $display("============================================");

        // ============================================================
        // Phase 1: Reset
        // ============================================================
        rst = 1;
        repeat(4) @(posedge clk);

        // ============================================================
        // Phase 2: Serial loading — MAX_W cycles, MSB first
        // ============================================================
        $display("Phase 2: Serial loading (%0d cycles)...", MAX_W);

        @(negedge clk);
        rst                = 0;
        keyxSI             = (MAX_W-1 >= KEY_OFF)   ? key_send  [MAX_W-1 - KEY_OFF]   : 1'b0;
        noncexSI           = (MAX_W-1 >= NONCE_OFF) ? nonce_send[MAX_W-1 - NONCE_OFF] : 1'b0;
        associated_dataxSI = (MAX_W-1 >= AD_OFF)    ? ad_send   [MAX_W-1 - AD_OFF]    : 1'b0;
        plain_textxSI      = (MAX_W-1 >= PT_OFF)    ? pt_send   [MAX_W-1 - PT_OFF]    : 1'b0;

        for (i = MAX_W-2; i >= 0; i = i - 1) begin
            @(negedge clk);
            keyxSI             = (i >= KEY_OFF)   ? key_send  [i - KEY_OFF]   : 1'b0;
            noncexSI           = (i >= NONCE_OFF) ? nonce_send[i - NONCE_OFF] : 1'b0;
            associated_dataxSI = (i >= AD_OFF)    ? ad_send   [i - AD_OFF]    : 1'b0;
            plain_textxSI      = (i >= PT_OFF)    ? pt_send   [i - PT_OFF]    : 1'b0;
        end

        @(negedge clk);
        keyxSI = 0; noncexSI = 0; associated_dataxSI = 0; plain_textxSI = 0;
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
        $display("  PT    : %h  %s", uut.plain_text,
                  (uut.plain_text      == `PT)    ? "MATCH" : "MISMATCH");
        $display("  i=%0d  ready=%b", uut.i, uut.ready);
        $display("--------------------------------------------");
        $display("Initial state S = IV||K||N (before p12):");
        $display("  S0=%h", uut.encryption_core.S[319:256]);
        $display("  S1=%h", uut.encryption_core.S[255:192]);
        $display("  S2=%h", uut.encryption_core.S[191:128]);
        $display("  S3=%h", uut.encryption_core.S[127:64]);
        $display("  S4=%h", uut.encryption_core.S[63:0]);
        $display("--------------------------------------------");

        if (uut.key !== `KEY || uut.nonce !== `NONCE ||
            uut.associated_data !== `AD || uut.plain_text !== `PT) begin
            $display("ERROR: Serial loading mismatch. Aborting.");
            $finish;
        end

        // ============================================================
        // Phase 3: Start encryption
        // ============================================================
        @(negedge clk);
        encryption_startxSI = 1;
        start_time = $time;
        repeat(2) @(posedge clk);
        @(negedge clk);
        encryption_startxSI = 0;
        $display("Phase 3: Encryption started.");

        // ============================================================
        // INITIALIZATION p12
        // ============================================================
        $display("--------------------------------------------");
        $display("INITIALIZATION p12 (%0d rounds):", `a);
        wait(uut.encryption_core.state == 1);

        @(posedge clk);
        $display("  [loaded]: x0=%h x1=%h x2=%h x3=%h x4=%h",
            uut.encryption_core.p1.x0_q, uut.encryption_core.p1.x1_q,
            uut.encryption_core.p1.x2_q, uut.encryption_core.p1.x3_q,
            uut.encryption_core.p1.x4_q);
        repeat(`a) begin
            @(posedge clk);
            $display("  round   : x0=%h x1=%h x2=%h x3=%h x4=%h",
                uut.encryption_core.p1.x0_q, uut.encryption_core.p1.x1_q,
                uut.encryption_core.p1.x2_q, uut.encryption_core.p1.x3_q,
                uut.encryption_core.p1.x4_q);
        end

        wait(uut.encryption_core.state != 1);
        @(posedge clk);
        $display("--------------------------------------------");
        $display("State after p12 + key XOR:");
        $display("  S0=%h", uut.encryption_core.S[319:256]);
        $display("  S1=%h", uut.encryption_core.S[255:192]);
        $display("  S2=%h", uut.encryption_core.S[191:128]);
        $display("  S3=%h", uut.encryption_core.S[127:64]);
        $display("  S4=%h", uut.encryption_core.S[63:0]);
        $display("--------------------------------------------");

        // ============================================================
        // ASSOCIATED DATA — one display per block (skipped if l == 0)
        // ============================================================
        if (S_BLK > 0) begin
            $display("============================================");
            $display("  AD ABSORPTION (%0d block(s))", S_BLK);
            $display("============================================");

            for (blk = 0; blk < S_BLK; blk = blk + 1) begin
                wait(uut.encryption_core.state == 2 &&
                     uut.encryption_core.block_ctr == blk);
                @(posedge clk);
                $display("  AD block %0d P_in: x0=%h x1=%h",
                    blk,
                    uut.encryption_core.P_in[319:256],
                    uut.encryption_core.P_in[255:192]);
                $display("             state x2=%h x3=%h x4=%h",
                    uut.encryption_core.P_in[191:128],
                    uut.encryption_core.P_in[127:64],
                    uut.encryption_core.P_in[63:0]);

                @(posedge uut.encryption_core.p1.done);
                @(posedge clk);
                $display("  AD block %0d done. S0=%h S1=%h",
                    blk,
                    uut.encryption_core.S[319:256],
                    uut.encryption_core.S[255:192]);
            end
        end

        // ============================================================
        // State after all AD + domain separation
        // ============================================================
        wait(uut.encryption_core.state == 3);
        @(posedge clk);
        $display("--------------------------------------------");
        $display("State after AD + domain sep:");
        $display("  S0=%h", uut.encryption_core.S[319:256]);
        $display("  S1=%h", uut.encryption_core.S[255:192]);
        $display("  S2=%h", uut.encryption_core.S[191:128]);
        $display("  S3=%h", uut.encryption_core.S[127:64]);
        $display("  S4=%h", uut.encryption_core.S[63:0]);
        $display("--------------------------------------------");

        // ============================================================
        // PLAINTEXT — one display per block (skipped if y == 0)
        // ============================================================
        if (T_BLK > 0) begin
            $display("============================================");
            $display("  PT/CT PROCESSING (%0d block(s))", T_BLK);
            $display("============================================");

            for (blk = 0; blk < T_BLK; blk = blk + 1) begin
                wait(uut.encryption_core.state == 3 &&
                     uut.encryption_core.block_ctr == blk);
                @(posedge clk);
                $display("  PT block %0d P_in:  x0=%h x1=%h",
                    blk,
                    uut.encryption_core.P_in[319:256],
                    uut.encryption_core.P_in[255:192]);
                $display("  PT block %0d C_d :  %h",
                    blk,
                    uut.encryption_core.C_d);

                if (blk < T_BLK - 1) begin
                    @(posedge uut.encryption_core.p1.done);
                    @(posedge clk);
                    $display("  PT block %0d done. S0=%h", blk, uut.encryption_core.S[319:256]);
                end
            end
        end

        // ============================================================
        // FINALIZE
        // ============================================================
        $display("--------------------------------------------");
        $display("Entering FINALIZE. S before key XOR:");
        wait(uut.encryption_core.state == 4);
        @(posedge clk);
        $display("  S0=%h", uut.encryption_core.S[319:256]);
        $display("  S1=%h", uut.encryption_core.S[255:192]);
        $display("  S2=%h", uut.encryption_core.S[191:128]);
        $display("  S3=%h", uut.encryption_core.S[127:64]);
        $display("  S4=%h", uut.encryption_core.S[63:0]);
        $display("  P_in (S^key): x0=%h x1=%h x2=%h x3=%h x4=%h",
            uut.encryption_core.P_in[319:256],
            uut.encryption_core.P_in[255:192],
            uut.encryption_core.P_in[191:128],
            uut.encryption_core.P_in[127:64],
            uut.encryption_core.P_in[63:0]);

        $display("--------------------------------------------");
        $display("FINALIZE p12 (%0d rounds):", `a);
        @(posedge clk);
        $display("  [loaded]: x0=%h x1=%h x2=%h x3=%h x4=%h",
            uut.encryption_core.p1.x0_q, uut.encryption_core.p1.x1_q,
            uut.encryption_core.p1.x2_q, uut.encryption_core.p1.x3_q,
            uut.encryption_core.p1.x4_q);
        repeat(`a) begin
            @(posedge clk);
            $display("  round   : x0=%h x1=%h x2=%h x3=%h x4=%h",
                uut.encryption_core.p1.x0_q, uut.encryption_core.p1.x1_q,
                uut.encryption_core.p1.x2_q, uut.encryption_core.p1.x3_q,
                uut.encryption_core.p1.x4_q);
        end

        $display("--------------------------------------------");
        $display("P_out after finalize p12:");
        $display("  P_out[319:256]=%h", uut.encryption_core.P_out[319:256]);
        $display("  P_out[255:192]=%h", uut.encryption_core.P_out[255:192]);
        $display("  P_out[191:128]=%h", uut.encryption_core.P_out[191:128]);
        $display("  P_out[127:64] =%h", uut.encryption_core.P_out[127:64]);
        $display("  P_out[63:0]   =%h", uut.encryption_core.P_out[63:0]);
        $display("  Tag_d (comb)  =%h", uut.encryption_core.Tag_d);
        $display("  C (raw)       =%h", uut.encryption_core.C);
        @(posedge clk);
        $display("  Tag (latched) =%h", uut.encryption_core.Tag);
        $display("--------------------------------------------");

        // ============================================================
        // Phase 4: Wait for encryption_ready with timeout
        // ============================================================
        begin : wait_ready
            integer timeout;
            timeout = 0;
            while (!encryption_readyxSO && timeout < 2000) begin
                @(posedge clk);
                timeout = timeout + 1;
            end
            if (timeout >= 2000) begin
                $display("TIMEOUT waiting for encryption_ready");
                $finish;
            end
        end

        cycles_taken = ($time - start_time) / PERIOD;
        $display("Phase 4: Encryption complete in %0d cycles.", cycles_taken);

        // ============================================================
        // Phase 5: Capture serial output — CAPTURE cycles, LSB first.
        //
        // FIX: loop runs CAPTURE = max(y,128) times, not a hardcoded 128.
        // Each signal is independently gated so we never read past its
        // actual width.  This works correctly for any y:
        //   y <  128  → loop runs 128 times; CT gated at y, TAG full
        //   y == 128  → both run full 128 bits (identical to old code)
        //   y >  128  → loop runs y times; CT full, TAG gated at 128
        // ============================================================
        @(posedge clk);
        cipher_text[0] = cipher_textxSO;
        tag[0]         = tagxSO;

        for (i = 1; i < CAPTURE; i = i + 1) begin
            @(posedge clk);
            if (i < `y)   cipher_text[i] = cipher_textxSO;
            if (i < 128)  tag[i]         = tagxSO;
        end

        // ============================================================
        // Results
        // ============================================================
        $display("============================================");
        $display("              RESULTS");
        $display("============================================");
        $display("  Cycles  : %0d", cycles_taken);
        $display("  GOT CT  : %h", cipher_text);
        $display("  EXP CT  : %h  %s", `EXPECTED_CT,
                  (cipher_text == `EXPECTED_CT) ? "PASS" : "FAIL");
        $display("  GOT TAG : %h", tag);
        $display("  EXP TAG : %h  %s", `EXPECTED_TAG,
                  (tag == `EXPECTED_TAG) ? "PASS" : "FAIL");
        $display("============================================");
        $finish;
    end

endmodule
