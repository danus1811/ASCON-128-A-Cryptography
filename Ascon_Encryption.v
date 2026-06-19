// ASCON ENCRYPTION WRAPPER MODULE
//
// ENDIANNESS ANALYSIS (NIST SP 800-232):
//
// KEY  and NONCE: MUST be byte-swapped word-by-word.
//   They are placed directly into 64-bit state word slots:
//     S1 = key[127:64],  S2 = key[63:0]
//     S3 = nonce[127:64], S4 = nonce[63:0]
//   NIST requires S1 = 0x0706050403020100 for key = 0x000102...0f
//   The serial shift register captures MSB-first (big-endian), so
//   each 64-bit word must be byte-reversed before entering the core.
//
// AD and PT: NOT byte-swapped.
//   The core absorbs AD/PT as a MSB-first bit-string via:
//     assign A = {associated_data, 1'b1, {nz_ad{1'b0}}};
//   AD/PT bytes are placed at the MSB of the rate word (big-endian
//   within each word). This convention is internally consistent as
//   long as the reference implementation uses the same convention.
//
// TAG output: MUST be byte-swapped back.
//   Two 64-bit words must each be byte-reversed to produce the
//   big-endian tag that the user/testbench expects.
//
// CT output: NOT byte-swapped.
//   Same convention as PT input.

module Ascon_Encryption #(
    parameter k = 128,
    parameter r = 64,
    parameter a = 12,
    parameter b = 6,
    parameter l = 40,
    parameter y = 40,
    parameter v = 1
)(
    input       clk,
    input       rst,
    input       keyxSI,
    input       noncexSI,
    input       associated_dataxSI,
    input       plain_textxSI,
    input       encryption_startxSI,
    output reg  cipher_textxSO,
    output reg  tagxSO,
    output      encryption_readyxSO
);

    // ------------------------------------------------------------------
    // CNT_MAX: the counter must reach the largest of k, 128, l, y so
    // that every shift register receives its full complement of bits
    // before ready is asserted.  Hardcoding 128 broke configurations
    // where l > 128 or y > 128.
    // ------------------------------------------------------------------
    localparam CNT_MAX = (k  >= 128 ? k  : 128) >= l ?
                         (k  >= 128 ? k  : 128) >= y ?
                         (k  >= 128 ? k  : 128)       : y
                       : l >= y ? l : y;

    // ------------------------------------------------------------------
    // Internal shift registers - raw MSB-first serial capture
    // ------------------------------------------------------------------
    reg  [k-1:0]  key;
    reg  [127:0]  nonce;
    reg  [l-1:0]  associated_data;
    reg  [y-1:0]  plain_text;
    reg  [31:0]   i, j;

    // ------------------------------------------------------------------
    // bswap64: reverse byte order within one 64-bit word.
    // Converts the MSB-first (big-endian) serial-captured value
    // into the little-endian 64-bit integer the core state words need.
    // ------------------------------------------------------------------
    function [63:0] bswap64;
        input [63:0] x;
        bswap64 = { x[7:0],   x[15:8],  x[23:16], x[31:24],
                    x[39:32], x[47:40], x[55:48], x[63:56] };
    endfunction

    // ------------------------------------------------------------------
    // KEY: 128 bits = two 64-bit state words, each byte-swapped.
    // ------------------------------------------------------------------
    wire [127:0] key_le;
    assign key_le = { bswap64(key[127:64]),
                      bswap64(key[63:0])   };

    // ------------------------------------------------------------------
    // NONCE: 128 bits = two 64-bit state words, each byte-swapped.
    // ------------------------------------------------------------------
    wire [127:0] nonce_le;
    assign nonce_le = { bswap64(nonce[127:64]),
                        bswap64(nonce[63:0])   };

    // ------------------------------------------------------------------
    // CT: passed straight through from core to serial output.
    // ------------------------------------------------------------------
    wire [y-1:0] cipher_text;

    // ------------------------------------------------------------------
    // TAG: two 64-bit words in LE format from the core.
    // Byte-swap each word back to big-endian for the user.
    // ------------------------------------------------------------------
    wire [127:0] tag_core;
    wire [127:0] tag;
    assign tag = { bswap64(tag_core[127:64]),
                   bswap64(tag_core[63:0])   };

    // ------------------------------------------------------------------
    // Ready / start logic
    // ready is asserted once every shift register has been fully loaded.
    // The counter runs to CNT_MAX (not a hardcoded 128) so this works
    // for any combination of k, l, y.
    // ------------------------------------------------------------------
    wire ready            = (i >= k) && (i >= 128) && (i >= l) && (i >= y);
    wire encryption_start = ready & encryption_startxSI;
    wire encryption_ready;
    assign encryption_readyxSO = encryption_ready;

    // ------------------------------------------------------------------
    // Serial-in / serial-out shift registers
    // ------------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            key             <= 0;
            nonce           <= 0;
            associated_data <= 0;
            plain_text      <= 0;
            i               <= 0;
            j               <= 0;
            cipher_textxSO  <= 0;
            tagxSO          <= 0;
        end else begin
            // Shift in one bit per clock while the register still needs bits
            if (i < k)   key             <= {key[k-2:0],            keyxSI};
            if (i < 128) nonce           <= {nonce[126:0],           noncexSI};
            if (i < l)   associated_data <= {associated_data[l-2:0], associated_dataxSI};
            if (i < y)   plain_text      <= {plain_text[y-2:0],      plain_textxSI};

            // Counter: increment until we have clocked in CNT_MAX bits.
            // Using CNT_MAX instead of the previous hardcoded 128 ensures
            // all shift registers are fully loaded for any l or y > 128.
            if (i <= CNT_MAX) i <= i + 1;

            if (encryption_start)
                j <= 0;

            // Serialise outputs LSB-first once encryption is done
            if (encryption_ready) begin
                cipher_textxSO <= (j < y)   ? cipher_text[j] : 1'b0;
                tagxSO         <= (j < 128) ? tag[j]         : 1'b0;
                j <= j + 1;
            end
        end
    end

    // ------------------------------------------------------------------
    // Encryption core
    // ------------------------------------------------------------------
    Encryption #(k, r, a, b, l, y, v) encryption_core (
        .clk              (clk),
        .rst              (rst),
        .key              (key_le),
        .nonce            (nonce_le),
        .associated_data  (associated_data),
        .plain_text       (plain_text),
        .encryption_start (encryption_start),
        .cipher_text      (cipher_text),
        .tag              (tag_core),
        .encryption_ready (encryption_ready)
    );

endmodule
