
// =============================================================================
// ASCON TOP MODULE
// =============================================================================
// Directly instantiates Encryption and Decryption cores, removing the
// intermediate Ascon_Encryption / Ascon_Decryption wrapper layer.
// All endianness handling (bswap64) is done here for both cores.
// =============================================================================

module Ascon #(
    parameter k = 128,
    parameter r = 128,
    parameter a = 12,
    parameter b = 8,
    parameter l = 256,
    parameter y = 256,
    parameter v = 1
)(
    // Global
    input  clk,
    input  rst,

    // Serial inputs - shared by both cores
    input  keyxSI,
    input  noncexSI,
    input  associated_dataxSI,

    // Encryption side
    input  plain_textxSI,
    input  enc_startxSI,
    output reg enc_cipher_textxSO,
    output reg enc_tagxSO,
    output     enc_readyxSO,

    // Decryption side
    input  cipher_textxSI,
    input  dec_startxSI,
    output reg dec_plain_textxSO,
    output reg dec_tagxSO,
    output     dec_readyxSO
);

    // -----------------------------------------------------------------------
    // CNT_MAX: same logic as in the original wrapper
    // -----------------------------------------------------------------------
    localparam CNT_MAX = (k  >= 128 ? k  : 128) >= l ?
                         (k  >= 128 ? k  : 128) >= y ?
                         (k  >= 128 ? k  : 128)       : y
                       : l >= y ? l : y;

    // -----------------------------------------------------------------------
    // Shared shift registers (single load feeds both cores)
    // -----------------------------------------------------------------------
    reg [k-1:0]   key;
    reg [127:0]   nonce;
    reg [l-1:0]   associated_data;

    // Separate shift registers for PT (enc) and CT (dec)
    reg [y-1:0]   plain_text;
    reg [y-1:0]   cipher_text_in;

    // Shared input counter
    reg [8:0]    i;

    // Output serialisation counters
    reg [31:0]    j_enc;
    reg [31:0]    j_dec;

    // -----------------------------------------------------------------------
    // bswap64: byte-reverse a 64-bit word (LE <-> BE conversion)
    // -----------------------------------------------------------------------
    function [63:0] bswap64;
        input [63:0] x;
        bswap64 = { x[7:0],   x[15:8],  x[23:16], x[31:24],
                    x[39:32], x[47:40], x[55:48], x[63:56] };
    endfunction

    // -----------------------------------------------------------------------
    // Endianness-corrected key and nonce (shared by both cores)
    // -----------------------------------------------------------------------
    wire [127:0] key_le;
    wire [127:0] nonce_le;

    assign key_le   = { bswap64(key[127:64]),   bswap64(key[63:0])   };
    assign nonce_le = { bswap64(nonce[127:64]), bswap64(nonce[63:0]) };

    // -----------------------------------------------------------------------
    // Ready / start signals
    // -----------------------------------------------------------------------
    wire inputs_ready = (i >= k) && (i >= 128) && (i >= l) && (i >= y);

    wire enc_start = inputs_ready & enc_startxSI;
    wire dec_start = inputs_ready & dec_startxSI;

    wire encryption_ready;
    wire decryption_ready;

    assign enc_readyxSO = encryption_ready;
    assign dec_readyxSO = decryption_ready;

    // -----------------------------------------------------------------------
    // Encryption core outputs
    // -----------------------------------------------------------------------
    wire [y-1:0]   enc_cipher_text;   // Raw CT from enc core (no bswap needed)
    wire [127:0]   enc_tag_core;      // LE tag from enc core
    wire [127:0]   enc_tag;           // BE tag after bswap for user

    assign enc_tag = { bswap64(enc_tag_core[127:64]),
                       bswap64(enc_tag_core[63:0])   };

    // -----------------------------------------------------------------------
    // Decryption core outputs
    // -----------------------------------------------------------------------
    wire [y-1:0]   dec_plain_text;    // Raw PT from dec core
    wire [127:0]   dec_tag_core;      // LE tag from dec core
    wire [127:0]   dec_tag;           // BE tag after bswap for user

    assign dec_tag = { bswap64(dec_tag_core[127:64]),
                       bswap64(dec_tag_core[63:0])   };

    // -----------------------------------------------------------------------
    // Shared serial-in logic + per-core serial-out
    // -----------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            key                <= 0;
            nonce              <= 0;
            associated_data    <= 0;
            plain_text         <= 0;
            cipher_text_in     <= 0;
            i                  <= 0;
            j_enc              <= 0;
            j_dec              <= 0;
            enc_cipher_textxSO <= 0;
            enc_tagxSO         <= 0;
            dec_plain_textxSO  <= 0;
            dec_tagxSO         <= 0;
        end else begin

            // ----------------------------------------------------------
            // Shift in shared inputs (one bit per clock)
            // ----------------------------------------------------------
            if (i < k)   key             <= {key[k-2:0],            keyxSI};
            if (i < 128) nonce           <= {nonce[126:0],           noncexSI};
            if (i < l)   associated_data <= {associated_data[l-2:0], associated_dataxSI};

            // ----------------------------------------------------------
            // Shift in per-core inputs
            // ----------------------------------------------------------
            if (i < y)   plain_text      <= {plain_text[y-2:0],      plain_textxSI};
            if (i < y)   cipher_text_in  <= {cipher_text_in[y-2:0],  cipher_textxSI};

            // ----------------------------------------------------------
            // Input counter
            // ----------------------------------------------------------
            if (i <= CNT_MAX) i <= i + 1;

            // ----------------------------------------------------------
            // Reset output counters on start
            // ----------------------------------------------------------
            if (enc_start) j_enc <= 0;
            if (dec_start) j_dec <= 0;

            // ----------------------------------------------------------
            // Serialise encryption outputs (LSB first)
            // ----------------------------------------------------------
            if (encryption_ready) begin
                enc_cipher_textxSO <= (j_enc < y)   ? enc_cipher_text[j_enc] : 1'b0;
                enc_tagxSO         <= (j_enc < 128) ? enc_tag[j_enc]         : 1'b0;
                j_enc              <= j_enc + 1;
            end

            // ----------------------------------------------------------
            // Serialise decryption outputs (LSB first)
            // ----------------------------------------------------------
            if (decryption_ready) begin
                dec_plain_textxSO <= (j_dec < y)   ? dec_plain_text[j_dec] : 1'b0;
                dec_tagxSO        <= (j_dec < 128) ? dec_tag[j_dec]        : 1'b0;
                j_dec             <= j_dec + 1;
            end

        end
    end

    // -----------------------------------------------------------------------
    // Encryption core - direct instantiation
    // -----------------------------------------------------------------------
    Encryption #(
        .k (k), .r (r), .a (a), .b (b), .l (l), .y (y), .v (v)
    ) enc_core (
        .clk              (clk),
        .rst              (rst),
        .key              (key_le),
        .nonce            (nonce_le),
        .associated_data  (associated_data),
        .plain_text       (plain_text),
        .encryption_start (enc_start),
        .cipher_text      (enc_cipher_text),
        .tag              (enc_tag_core),
        .encryption_ready (encryption_ready)
    );

    // -----------------------------------------------------------------------
    // Decryption core - direct instantiation
    // -----------------------------------------------------------------------
    Decryption #(
        .k (k), .r (r), .a (a), .b (b), .l (l), .y (y), .v (v)
    ) dec_core (
        .clk              (clk),
        .rst              (rst),
        .key              (key_le),
        .nonce            (nonce_le),
        .associated_data  (associated_data),
        .cipher_text      (cipher_text_in),
        .decryption_start (dec_start),
        .plain_text       (dec_plain_text),
        .tag              (dec_tag_core),
        .decryption_ready (decryption_ready)
    );

endmodule


// Encryption FSM
module Encryption #(
    parameter k = 128,            // Key size
    parameter r = 128,            // Rate
    parameter a = 12,             // Initialization round no.
    parameter b = 8,              // Intermediate round no.
    parameter l = 256,             // Length of associated data
    parameter y = 256,             // Length of Plain Text
    parameter v = 1               // AEAD128 variant identifier
)(
    input           clk,
    input           rst,
    input  [k-1:0]  key,
    input  [127:0]  nonce,
    input  [l-1:0]  associated_data,
    input  [y-1:0]  plain_text,
    input           encryption_start,

    output [y-1:0]  cipher_text,
    output [127:0]  tag,
    output          encryption_ready
);
    // ---------------------------------------------------------------
    // Derived constants
    // ---------------------------------------------------------------
    parameter c = 320 - r;

    parameter nz_ad = ((l+1)%r == 0) ? 0 : r - ((l+1)%r);
    parameter L     = l + 1 + nz_ad;
    parameter s     = L / r;

    parameter nz_p  = ((y+1)%r == 0) ? 0 : r - ((y+1)%r);
    parameter Y     = y + 1 + nz_p;
    parameter t     = Y / r;
    parameter CTR_P = $clog2(t+1);


    // ---------------------------------------------------------------
    // Buffer variables
    // ---------------------------------------------------------------
    reg  [3:0]      rounds;
    reg  [127:0]    Tag;
    reg  [127:0]    Tag_d;
    reg             encryption_ready_1;
    wire [63:0]     IV;
    reg  [319:0]    S;
    wire [r-1:0]    Sr;
    wire [c-1:0]    Sc;
    reg  [319:0]    P_in;
    wire [319:0]    P_out;
    wire            permutation_ready;
    reg             permutation_start;
    reg  [L-1:0]    A;
    reg  [Y-1:0]    P;
    reg  [Y-1:0]    C;
    reg  [Y-1:0]    C_d;
    reg  [CTR_P-1:0]      block_ctr;
    integer         ki;
    localparam [7:0]  IV_rate = r >> 3;
    localparam [15:0] IV_k    = k;
    localparam [3:0]  IV_b    = b;
    localparam [3:0]  IV_a    = a;
    localparam [7:0]  IV_v    = v;

    assign IV = {
        16'h0000,
        IV_rate,
        IV_k,
        IV_b,
        IV_a,
        8'h00,
        IV_v
    };

   
    assign {Sr, Sc}         = S;
    assign encryption_ready = encryption_ready_1;
    assign tag              = (encryption_ready_1) ? Tag : 0;

    // ---------------------------------------------------------------
    // cipher_text byte-reorder (unchanged)
    // ---------------------------------------------------------------
    wire [y-1:0] cipher_text_brev;
    genvar ci;
    generate
        for (ci = 0; ci < y/8; ci = ci + 1) begin : gen_ct_brev
            assign cipher_text_brev[y-1 - 8*ci -: 8] =
                C[(Y/64 - 1 - ci/8)*64 + (ci%8)*8 +: 8];
        end
    endgenerate

    assign cipher_text = (encryption_ready_1) ? cipher_text_brev : 0;

    // ---------------------------------------------------------------
    // FSM States
    // ---------------------------------------------------------------
    parameter IDLE            = 'd0,
              INITIALIZE      = 'd1,
              ASSOCIATED_DATA = 'd2,
              PTCT            = 'd3,
              FINALIZE        = 'd4,
              DONE            = 'd5,
              FINALIZE_PREP   = 'd6;
    reg [2:0] state;

    // ---------------------------------------------------------------
    // Sequential Block
    // ---------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state     <= IDLE;
            S         <= 0;
            Tag       <= 0;
            C         <= 0;
            block_ctr <= 0;
        end
        else begin
            case (state)

                IDLE: begin
                    S         <= {IV, key, nonce};
                    C         <= 0;
                    block_ctr <= 0;
                    if (encryption_start)
                        state <= INITIALIZE;
                end

                INITIALIZE: begin
                    if (permutation_ready) begin
                        if (l != 0) begin
                            state <= ASSOCIATED_DATA;
                            S     <= P_out ^ {{(320-k){1'b0}}, key};
                        end
                        else if (l == 0 && y != 0) begin
                            state <= PTCT;
                            S     <= (P_out ^ {{(320-k){1'b0}}, key})
                                     ^ {256'b0, 1'b1, 63'b0};
                        end
                        else begin
                            state <= FINALIZE_PREP;
                            S     <= (P_out ^ {{(320-k){1'b0}}, key})
                                     ^ {256'b0, 1'b1, 63'b0};
                        end
                    end
                end

                ASSOCIATED_DATA: begin
                    if (permutation_ready && block_ctr == s-1) begin
                        block_ctr <= 0;
                        if (y != 0) begin
                            state <= PTCT;
                            S     <= P_out ^ {256'b0, 1'b1, 63'b0};
                        end
                        else begin
                            state <= FINALIZE_PREP;
                            S     <= P_out ^ {256'b0, 1'b1, 63'b0};
                        end
                    end
                    else if (permutation_ready && block_ctr < s-1) begin
                        S         <= P_out;
                        block_ctr <= block_ctr + 1;
                    end
                end

                PTCT: begin
                    if (permutation_ready && block_ctr == t-1) begin
                        block_ctr <= 0;
                        state     <= FINALIZE_PREP;
                        S <= {Sr ^ P[Y-1-(block_ctr*r) -: r], Sc};
                        C <= C | C_d;
                    end
                    else if (permutation_ready && block_ctr < t-1) begin
                        S         <= P_out;
                        C         <= C | C_d;
                        block_ctr <= block_ctr + 1;
                    end
                end

                FINALIZE_PREP: begin
                    state <= FINALIZE;
                end

                FINALIZE: begin
                    if (permutation_ready) begin
                        S     <= P_out;
                        state <= DONE;
                        Tag   <= Tag_d;
                    end
                end

                DONE: begin
                    if (encryption_start) begin
                        state     <= IDLE;
                        C         <= 0;
                        block_ctr <= 0;
                        Tag       <= 0;
                    end
                end

                default:
                    state <= IDLE;

            endcase
        end
    end

    // ---------------------------------------------------------------
    // Combinational Block
    // ---------------------------------------------------------------
    always @(*) begin
        C_d   = 0;
        Tag_d = 0;
        encryption_ready_1 = 0;

        // --- Build A ---
        A = {L{1'b0}};
        for (ki = 0; ki < L/8; ki = ki + 1) begin
            if (ki < l/8)
                A[(L/64 - 1 - ki/8)*64 + (ki%8)*8 +: 8] =
                    associated_data[l-1 - ki*8 -: 8];
            else if (ki == l/8)
                A[(L/64 - 1 - ki/8)*64 + (ki%8)*8 +: 8] = 8'h01;
        end

        // --- Build P ---
        P = {Y{1'b0}};
        for (ki = 0; ki < Y/8; ki = ki + 1) begin
            if (ki < y/8)
                P[(Y/64 - 1 - ki/8)*64 + (ki%8)*8 +: 8] =
                    plain_text[y-1 - ki*8 -: 8];
            else if (ki == y/8)
                P[(Y/64 - 1 - ki/8)*64 + (ki%8)*8 +: 8] = 8'h01;
        end

        case (state)
            IDLE: begin
                permutation_start  = 0;
                rounds             = a;
                P_in               = S;
            end

            INITIALIZE: begin
                rounds             = a;
                permutation_start  = (permutation_ready) ? 1'b0 : 1'b1;
                P_in               = S;
            end

            ASSOCIATED_DATA: begin
                rounds             = b;
                if (permutation_ready && block_ctr == (s-1))
                    permutation_start = 0;
                else
                    permutation_start = 1;
                P_in = {Sr ^ A[L-1-(block_ctr*r) -: r], Sc};
            end

            PTCT: begin
                rounds = b;
                C_d[Y-1-(block_ctr*r) -: r] = Sr ^ P[Y-1-(block_ctr*r) -: r];
                P_in   = {Sr ^ P[Y-1-(block_ctr*r) -: r], Sc};
                if (permutation_ready && block_ctr == (t-1))
                    permutation_start = 0;
                else
                    permutation_start = 1;
            end

            FINALIZE_PREP: begin
                rounds            = a;
                P_in              = S ^ ({{r{1'b0}}, key, {(c-k){1'b0}}});
                permutation_start = 0;
            end

            FINALIZE: begin
                rounds            = a;
                P_in              = S ^ ({{r{1'b0}}, key, {(c-k){1'b0}}});
                permutation_start = (permutation_ready) ? 1'b0 : 1'b1;
                Tag_d             = P_out[k-1:0] ^ key;
            end

            DONE: begin
                rounds             = a;
                P_in               = 0;
                permutation_start  = 0;
                encryption_ready_1 = 1;
            end

            default: begin
                rounds            = 0;
                P_in              = S;
                permutation_start = 0;
            end
        endcase
    end

    // ---------------------------------------------------------------
    // Permutation instance (merged, no RoundCounter needed)
    // ---------------------------------------------------------------
    Permutation p1 (
        .clk    (clk),
        .reset  (rst),
        .S      (P_in),
        .out    (P_out),
        .done   (permutation_ready),
        .rounds (rounds),
        .start  (permutation_start)
    );

endmodule


// Decryption FSM
// Mirrors Encryption FSM structure exactly.
module Decryption #(
    parameter k = 128,            // Key size
    parameter r = 128,            // Rate  (128 for AEAD128)
    parameter a = 12,             // Initialization round count
    parameter b = 8,              // Intermediate round count
    parameter l = 256,             // Length of associated data (bits)
    parameter y = 256,             // Length of cipher text (bits)
    parameter v = 1               // AEAD128 variant identifier
)(
    input           clk,
    input           rst,
    input  [k-1:0]  key,
    input  [127:0]  nonce,
    input  [l-1:0]  associated_data,
    input  [y-1:0]  cipher_text,
    input           decryption_start,

    output [y-1:0]  plain_text,
    output [127:0]  tag,
    output          decryption_ready
);
    // -----------------------------------------------------------------------
    // Derived constants
    // -----------------------------------------------------------------------
    parameter c = 320 - r;

    parameter nz_ad = ((l+1)%r == 0) ? 0 : r - ((l+1)%r);
    parameter L     = l + 1 + nz_ad;
    parameter s     = L / r;

    parameter nz_p  = ((y+1)%r == 0) ? 0 : r - ((y+1)%r);
    parameter Y     = y + 1 + nz_p;
    parameter t     = Y / r;
    parameter CTR_P = $clog2(t+1);

    // -----------------------------------------------------------------------
    // Internal signals
    // -----------------------------------------------------------------------
    reg  [3:0]   rounds;
    reg  [127:0] Tag;
    reg  [127:0] Tag_d;
    reg          decryption_ready_1;

    // IV: identical layout to the encryption IV
    wire [63:0] IV;
    localparam [7:0]  IV_rate = r >> 3;
    localparam [15:0] IV_k    = k;
    localparam [3:0]  IV_b    = b;
    localparam [3:0]  IV_a    = a;
    localparam [7:0]  IV_v    = v;

    assign IV = {
        16'h0000,
        IV_rate,
        IV_k,
        IV_b,
        IV_a,
        8'h00,
        IV_v
    };

    reg  [319:0] S;
    wire [r-1:0] Sr;
    wire [c-1:0] Sc;
    assign {Sr, Sc} = S;

    reg  [319:0] P_in;
    wire [319:0] P_out;
    wire         permutation_ready;
    reg          permutation_start;

    reg  [L-1:0] A;
    reg  [Y-1:0] C;
    reg  [Y-1:0] P;
    reg  [Y-1:0] P_d;
    reg  [CTR_P-1:0]   block_ctr;
    integer      ki;

    // FIX: Declare module-scope regs for CTPT last-block processing
    reg  [r-1:0] P_padded_last;       // <-- ADDED
    integer      local_bki;           // <-- ADDED

    assign decryption_ready = decryption_ready_1;
    assign tag = (decryption_ready_1) ? Tag : 0;

    // -----------------------------------------------------------------------
    // plain_text byte extraction (unchanged)
    // -----------------------------------------------------------------------
    wire [y-1:0] plain_text_out;
    genvar pi;
    generate
        for (pi = 0; pi < y/8; pi = pi + 1) begin : gen_pt_extract
            assign plain_text_out[y-1 - 8*pi -: 8] =
                P[(Y/64 - 1 - pi/8)*64 + (pi%8)*8 +: 8];
        end
    endgenerate
    assign plain_text = (decryption_ready_1) ? plain_text_out : 0;

    // -----------------------------------------------------------------------
    // FSM States
    // -----------------------------------------------------------------------
    parameter IDLE            = 'd0,
              INITIALIZE      = 'd1,
              ASSOCIATED_DATA = 'd2,
              CTPT            = 'd3,
              FINALIZE        = 'd4,
              DONE            = 'd5,
              FINALIZE_PREP   = 'd6;
    reg [2:0] state;

    // -----------------------------------------------------------------------
    // Sequential Block
    // -----------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            state     <= IDLE;
            S         <= 0;
            Tag       <= 0;
            P         <= 0;
            block_ctr <= 0;
        end else begin
            case (state)

                IDLE: begin
                    S         <= {IV, key, nonce};
                    P         <= 0;
                    block_ctr <= 0;
                    if (decryption_start)
                        state <= INITIALIZE;
                end

                INITIALIZE: begin
                    if (permutation_ready) begin
                        if (l != 0) begin
                            state <= ASSOCIATED_DATA;
                            S     <= P_out ^ {{(320-k){1'b0}}, key};
                        end else if (l == 0 && y != 0) begin
                            state <= CTPT;
                            S     <= (P_out ^ {{(320-k){1'b0}}, key})
                                     ^ {256'b0, 1'b1, 63'b0};
                        end else begin
                            state <= FINALIZE_PREP;
                            S     <= (P_out ^ {{(320-k){1'b0}}, key})
                                     ^ {256'b0, 1'b1, 63'b0};
                        end
                    end
                end

                ASSOCIATED_DATA: begin
                    if (permutation_ready && block_ctr == s-1) begin
                        block_ctr <= 0;
                        if (y != 0) begin
                            state <= CTPT;
                            S     <= P_out ^ {256'b0, 1'b1, 63'b0};
                        end else begin
                            state <= FINALIZE_PREP;
                            S     <= P_out ^ {256'b0, 1'b1, 63'b0};
                        end
                    end else if (permutation_ready && block_ctr < s-1) begin
                        S         <= P_out;
                        block_ctr <= block_ctr + 1;
                    end
                end

                CTPT: begin
                    if (permutation_ready && block_ctr == t-1) begin
                        block_ctr <= 0;
                        state     <= FINALIZE_PREP;
                        S         <= P_in;
                        P         <= P | P_d;
                    end else if (permutation_ready && block_ctr < t-1) begin
                        S         <= P_out;
                        P         <= P | P_d;
                        block_ctr <= block_ctr + 1;
                    end
                end

                FINALIZE_PREP: begin
                    state <= FINALIZE;
                end

                FINALIZE: begin
                    if (permutation_ready) begin
                        S     <= P_out;
                        state <= DONE;
                        Tag   <= Tag_d;
                    end
                end

                DONE: begin
                    if (decryption_start) begin
                        state     <= IDLE;
                        P         <= 0;
                        block_ctr <= 0;
                        Tag       <= 0;
                    end
                end

                default: state <= IDLE;
            endcase
        end
    end

    // -----------------------------------------------------------------------
    // Combinational Block
    // -----------------------------------------------------------------------
    always @(*) begin
        P_d                = 0;
        Tag_d              = 0;
        decryption_ready_1 = 0;

        // --- Build A ---
        A = {L{1'b0}};
        for (ki = 0; ki < L/8; ki = ki + 1) begin
            if (ki < l/8)
                A[(L/64 - 1 - ki/8)*64 + (ki%8)*8 +: 8] =
                    associated_data[l-1 - ki*8 -: 8];
            else if (ki == l/8)
                A[(L/64 - 1 - ki/8)*64 + (ki%8)*8 +: 8] = 8'h01;
        end

        // --- Build C (padded ciphertext, LE word format) ---
        C = {Y{1'b0}};
        for (ki = 0; ki < Y/8; ki = ki + 1) begin
            if (ki < y/8)
                C[(Y/64 - 1 - ki/8)*64 + (ki%8)*8 +: 8] =
                    cipher_text[y-1 - ki*8 -: 8];
            else if (ki == y/8)
                C[(Y/64 - 1 - ki/8)*64 + (ki%8)*8 +: 8] = 8'h01;
        end

        case (state)
            IDLE: begin
                permutation_start  = 0;
                rounds             = a;
                P_in               = S;
            end

            INITIALIZE: begin
                rounds             = a;
                permutation_start  = (permutation_ready) ? 1'b0 : 1'b1;
                P_in               = S;
            end

            ASSOCIATED_DATA: begin
                rounds             = b;
                if (permutation_ready && block_ctr == s-1)
                    permutation_start = 0;
                else
                    permutation_start = 1;
                P_in = {Sr ^ A[L-1-(block_ctr*r) -: r], Sc};
            end

            CTPT: begin
                rounds = b;
                if (block_ctr < t-1) begin
                    P_d[Y-1-(block_ctr*r) -: r] = Sr ^ C[Y-1-(block_ctr*r) -: r];
                    P_in = {C[Y-1-(block_ctr*r) -: r], Sc};
                end else begin
                    P_padded_last = {r{1'b0}};
                    for (local_bki = 0; local_bki < r/8; local_bki = local_bki + 1) begin
                        if ((block_ctr*(r/8) + local_bki) < Y/8) begin
                            if ((block_ctr*(r/8) + local_bki) < y/8) begin
                                P_d[(Y/64 - 1 - (block_ctr*(r/8) + local_bki)/8)*64 +
                                    ((block_ctr*(r/8) + local_bki)%8)*8 +: 8] =
                                        Sr[(r/64 - 1 - local_bki/8)*64 +
                                            (local_bki%8)*8 +: 8] ^
                                        C[(Y/64 - 1 - (block_ctr*(r/8) + local_bki)/8)*64 +
                                            ((block_ctr*(r/8) + local_bki)%8)*8 +: 8];

                                P_padded_last[(r/64 - 1 - local_bki/8)*64 +
                                              (local_bki%8)*8 +: 8] =
                                        Sr[(r/64 - 1 - local_bki/8)*64 +
                                            (local_bki%8)*8 +: 8] ^
                                        C[(Y/64 - 1 - (block_ctr*(r/8) + local_bki)/8)*64 +
                                            ((block_ctr*(r/8) + local_bki)%8)*8 +: 8];

                            end else if ((block_ctr*(r/8) + local_bki) == y/8) begin
                                P_padded_last[(r/64 - 1 - local_bki/8)*64 +
                                              (local_bki%8)*8 +: 8] = 8'h01;
                            end
                        end
                    end
                    P_in = {Sr ^ P_padded_last, Sc};
                end
                if (permutation_ready && block_ctr == t-1)
                    permutation_start = 0;
                else
                    permutation_start = 1;
            end

            FINALIZE_PREP: begin
                rounds            = a;
                P_in              = S ^ ({{r{1'b0}}, key, {(c-k){1'b0}}});
                permutation_start = 0;
            end

            FINALIZE: begin
                rounds            = a;
                P_in              = S ^ ({{r{1'b0}}, key, {(c-k){1'b0}}});
                permutation_start = (permutation_ready) ? 1'b0 : 1'b1;
                Tag_d             = P_out[k-1:0] ^ key;
            end

            DONE: begin
                decryption_ready_1 = 1;
                rounds             = a;
                P_in               = 0;
                permutation_start  = 0;
            end

            default: begin
                rounds            = 0;
                P_in              = S;
                permutation_start = 0;
            end
        endcase
    end

    // -----------------------------------------------------------------------
    // Permutation instance (merged, no RoundCounter needed)
    // -----------------------------------------------------------------------
    Permutation p1 (
        .clk    (clk),
        .reset  (rst),
        .S      (P_in),
        .out    (P_out),
        .done   (permutation_ready),
        .rounds (rounds),
        .start  (permutation_start)
    );

endmodule





module roundconstant (
    input  [63:0] x2,
    input  [3:0] ctr,          // 0 to rounds-1 
    input  [3:0] rounds,       // a or b value
    output [63:0] out
);

    reg [7:0] rc;
    
    // wire [4:0] index;
    wire [3:0] index;

    // Offset calculation
    // FIX: use (15 - rounds) instead of (16 - rounds).
    // RoundCounter increments ctr on the same posedge that Permutation
    // loads x_q from S. So when x_q=S is first available for round 1
    // computation, ctr is already 1 (not 0). Subtracting 1 corrects this.

    // p12 round 1: ctr=1, index = 1+(16-12)-1 = 4 -> rc=0xf0 ?
    // p12 round 12: ctr=12, index = 12+(16-12)-1 = 15 -> rc=0x4b ?
    // p8  round 1: ctr=1, index = 1+(16-8)-1 = 8  -> rc=0xb4 ?
    
    assign index = ctr + (15 - rounds);

    always @(*) begin
        case (index)
		4'd0:  rc = 8'h3c;   // const0
		4'd1:  rc = 8'h2d;   // const1
		4'd2:  rc = 8'h1e;   // const2
		4'd3:  rc = 8'h0f;   // const3
		4'd4:  rc = 8'hf0;   // const4  ? p12 starts here
		4'd5:  rc = 8'he1;   // const5
		4'd6:  rc = 8'hd2;   // const6
		4'd7:  rc = 8'hc3;   // const7
		4'd8:  rc = 8'hb4;   // const8  ? p8 starts here
		4'd9:  rc = 8'ha5;   // const9
		4'd10: rc = 8'h96;   // const10 ? p6 starts here
		4'd11: rc = 8'h87;   // const11
		4'd12: rc = 8'h78;   // const12
		4'd13: rc = 8'h69;   // const13
		4'd14: rc = 8'h5a;   // const14
		4'd15: rc = 8'h4b;   // const15
            default: rc = 8'h00;
        endcase
    end

    assign out = x2 ^ {56'b0, rc};

endmodule

module linear_layer (
    input  [63:0] X0, X1, X2, X3, X4,
    output [63:0] Y0, Y1, Y2, Y3, Y4
);
    // Right rotation macro: (X >> N) | (X << (64-N))
    // Since X is [63:0], Verilog handles 64-bit arithmetic correctly
    // No manual masking needed

    assign Y0 = X0 ^ ((X0 >> 6'd19) | (X0 << 6'd45))
                   ^ ((X0 >> 6'd28) | (X0 << 6'd36));

    assign Y1 = X1 ^ ((X1 >> 6'd61) | (X1 << 6'd3))
                   ^ ((X1 >> 6'd39) | (X1 << 6'd25));

    assign Y2 = X2 ^ ((X2 >> 6'd1)  | (X2 << 6'd63))
                   ^ ((X2 >> 6'd6)  | (X2 << 6'd58));

    assign Y3 = X3 ^ ((X3 >> 6'd10) | (X3 << 6'd54))
                   ^ ((X3 >> 6'd17) | (X3 << 6'd47));

    assign Y4 = X4 ^ ((X4 >> 6'd7)  | (X4 << 6'd57))
                   ^ ((X4 >> 6'd41) | (X4 << 6'd23));
endmodule

module sub_layer (
    input [63:0] x0, x1, x2, x3, x4,
    output [63:0] s10, s11, s12, s13, s14
);
        assign s10 = (x4 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ (x1 & x0) ^ x1 ^ x0;      
        assign s11 = x4 ^ (x3 & x2) ^ (x3 & x1) ^ x3 ^ x2 ^ x1 ^ x0 ^ (x2 & x1);
        assign s12 = (x4 & x3) ^ x4 ^ x2 ^ x1 ^ 64'hffffffffffffffff;               
        assign s13 = (x4 & x0) ^ (x3 & x0) ^ x4 ^ x3 ^ x2 ^x1 ^ x0;                 
        assign s14 = (x4 & x1) ^ x4 ^ x3 ^ (x1 & x0) ^ x1;                          
endmodule

module Permutation (
    input           clk,
    input           reset,
    input   [319:0] S,
    input   [3:0]   rounds,
    input           start,
    output  [319:0] out,
    output          done
);
    // ----------------------------------------------------------------
    // Internal counter (was RoundCounter)
    // ----------------------------------------------------------------
    reg  [3:0] ctr;
    reg done_r;

    always @(posedge clk) begin
        if (reset)
            ctr <= 0;
        else begin
            if (done_r || ~start)       // last round reached, or idle
                ctr <= 0;
            else
                ctr <= ctr + 1;
        end
    end

    // ----------------------------------------------------------------
    // State registers
    // ----------------------------------------------------------------
    reg  [63:0] x0_q, x1_q, x2_q, x3_q, x4_q;
    wire [63:0] x0_d, x1_d, x2_d, x3_d, x4_d;

    always @(posedge clk) begin
        if (reset)
            {x0_q, x1_q, x2_q, x3_q, x4_q} <= 0;
        else if (start) begin
            if (ctr == 0)
                {x0_q, x1_q, x2_q, x3_q, x4_q} <= S;
            else begin
                x0_q <= x0_d;
                x1_q <= x1_d;
                x2_q <= x2_d;
                x3_q <= x3_d;
                x4_q <= x4_d;
            end
        end
    end

    always @(posedge clk) begin
        if (reset)
            done_r <= 0;
        else if (~start)
            done_r <= 0;
        else
            done_r <= (ctr == rounds);
    end

    assign done = done_r;

    // ----------------------------------------------------------------
    // Output
    // ----------------------------------------------------------------
    assign out = {x0_q, x1_q, x2_q, x3_q, x4_q};

    // ----------------------------------------------------------------
    // Round Constant layer
    // ----------------------------------------------------------------
    wire [63:0] rc_out;
    roundconstant u0 (
        .x2    (x2_q),
        .ctr   (ctr),
        .out   (rc_out),
        .rounds(rounds)
    );

    // ----------------------------------------------------------------
    // Substitution layer
    // ----------------------------------------------------------------
    wire [63:0] s10, s11, s12, s13, s14;
    sub_layer u1 (
        .x0 (x0_q), .x1(x1_q), .x2(rc_out),
        .x3 (x3_q), .x4(x4_q),
        .s10(s10),  .s11(s11), .s12(s12),
        .s13(s13),  .s14(s14)
    );

    // ----------------------------------------------------------------
    // Linear diffusion layer
    // ----------------------------------------------------------------
    linear_layer u2 (
        .X0(s10), .X1(s11), .X2(s12), .X3(s13), .X4(s14),
        .Y0(x0_d), .Y1(x1_d), .Y2(x2_d), .Y3(x3_d), .Y4(x4_d)
    );

endmodule