const STATE_LEN: usize = 5;
const BLOCK_LEN_BITS: usize = 512;

/// Constants defined in section 5.
/// ( 0 <= t <= 19)
const K0: u32 = 0x5A827999u32;
/// (20 <= t <= 39)
const K1: u32 = 0x6ED9EBA1u32;
/// (40 <= t <= 59)
const K2: u32 = 0x8F1BBCDCu32;
/// (60 <= t <= 79)
const K3: u32 = 0xCA62C1D6u32;

/// Equation defined in section 5 for 0<=t<=19
fn f_of_t_0_to_19(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | ((!b) & d)
}

/// Equation defined in section 5 for 20<=t<=39
fn f_of_t_20_to_39(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

/// Equation defined in section 5 for 40<=t<=59
fn f_of_t_40_to_59(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (b & d) | (c & d)
}

/// Equation defined in section 5 for 60<=t<=79
fn f_of_t_60_to_79(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

/// Constants H0, .., H4 in section 6.1.
const H: [u32; STATE_LEN] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// Toy SHA-1 implementation
///
/// If you are thinking of using this in production code, do not.
/// This is merely a toy / annotated implementation for learning purposes.
/// Use [RustCrypto's SHA-1 implementation](https://github.com/RustCrypto/hashes) instead.
///
/// # Usage
///
/// ```rust
/// # use hashes::Sha1;
/// # fn main() {
/// let mut m = Sha1::new();
/// m.update("Hello peeps".as_bytes());
/// assert_eq!(&*m.hexdigest(), "cfe4171277bef90e1bbbc959638c6dd06d3f43db");
/// # }
/// ```
///
/// # How SHA-1 works
///
/// SHA-1 is defined in [RFC 3174](https://www.ietf.org/rfc/rfc3174.txt), which this exposition follows.
/// SHA-1 takes as input a message that is less than 2^64 in length.
/// It outputs a 160 bit message digest.
///
/// ## Definitions
///
/// The below definitions are from section 2 of the RFC:
///
/// * A *hex digit* represents a 4 bit string.
///
/// * A *word* represents a 32 bit string, i.e. 8 hex digits. An int between 0 and 2^32-1 is also a word.
///
/// * A block is a 512 bit string, which is also 16 words.
///
/// ## Basic operations
///
/// The basic operations we perform are bitwise and are performed on words.
///
/// They are:
///
/// * AND (&),
/// * OR (|),
/// * XOR (^),
/// * NOT (!),
/// * Circular left shift: S^n(X) = (X << n) OR (X >> 32-n)
/// * z = (x + y) mod 2^32
///
/// ## Padding
///
/// We pad the input such that it is a multiple of 512 (bits) as
/// SHA processes blocks of 512 bits.
/// We add "1", then m "0"s, then a 64-bit integer representing the
/// length of the message. This produces n 512 bit blocks.
///
/// ## Message Digest
/// There are two methods to compute the message digest described in the specification.
/// This implementation follows the procedure described in section 6.1.
/// We use two buffers of 5 32-bit words. One of these is stored on the Sha1 struct in this
/// implementation as the state field. This state field is initialized using constants defined
/// in the spec, and updated each time a block if processed.
/// A temporary buffer of 80 words is also used during processing of each block.
/// Each block is processed in series, from left to right. The detailed steps are described inline
/// in the method `Sha1::process_block`.
///
/// Based on mitsuhiko/rust-sha1 and kstep/rust-sha1-hasher
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; STATE_LEN],
    blocks: Vec<u8>,
    len: u64,
}

impl Sha1 {
    pub fn new() -> Sha1 {
        Sha1 {
            state: H,
            blocks: Vec::with_capacity(256),
            len: 0,
        }
    }

    /// For attack purposes
    pub fn set_len(&mut self, len: u64) {
        self.len = len;
    }

    /// For attack purposes
    pub fn new_state(state: [u32; STATE_LEN]) -> Sha1 {
        Sha1 {
            state,
            blocks: Vec::with_capacity(256),
            len: 0,
        }
    }

    /// Resets the Sha1 struct to the starting state.
    pub fn reset(&mut self) {
        self.state = H;
        self.blocks.clear();
        self.len = 0;
    }

    /// Output the final Sha1 digest in hex.
    pub fn hexdigest(&mut self) -> String {
        let result = self.compute();
        to_hex(&result[..])
    }

    pub fn bytes(&mut self) -> Vec<u8> {
        let result = self.compute();
        result
    }

    /// Provide some input data to the Sha1 struct for processing.
    pub fn update(&mut self, bytes: &[u8]) {
        let mut d = self.blocks.clone();
        self.blocks.clear();

        d.extend_from_slice(bytes);

        for chunk in d[..].chunks(64) {
            if chunk.len() == 64 {
                self.len += 64;
                self.process_block(chunk);
            } else {
                self.blocks.extend_from_slice(chunk);
            }
        }
    }

    /// Process a single block.
    fn process_block(&mut self, block: &[u8]) {
        let mut words = [0u32; 80];
        let mut j = 0;

        // 6.1a. Divide M(i) into 16 words W(0), W(1), ... , W(15), where W(0)
        // is the left-most word.
        for i in (0..block.len()).step_by(4) {
            words[j] = (block[i + 3] as u32)
                | ((block[i + 2] as u32) << 8)
                | ((block[i + 1] as u32) << 16)
                | ((block[i] as u32) << 24);
            j += 1;
        }

        // 6.1b. For t = 16 to 79 let
        // W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)).
        for t in 16..80 {
            let n = words[t - 3] ^ words[t - 8] ^ words[t - 14] ^ words[t - 16];
            words[t] = n.rotate_left(1);
        }

        // 6.1c. Let A = H0, B = H1, C = H2, D = H3, E = H4.
        // This sets A, B, C, D, E to H0..H4 initially. Thereafter, it uses the value from the last
        // iteration of block processing.
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        // d. For t = 0 to 79 do
        // TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
        // E = D; D = C; C = S^30(B); B = A; A = TEMP;
        for t in 0..=79 {
            let (f, k) = match t {
                0..=19 => (f_of_t_0_to_19(b, c, d), K0),
                20..=39 => (f_of_t_20_to_39(b, c, d), K1),
                40..=59 => (f_of_t_40_to_59(b, c, d), K2),
                60..=79 => (f_of_t_60_to_79(b, c, d), K3),
                _ => panic!("should be unreachable, got an invalid block num"),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(words[t])
                .wrapping_add(k);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // 6.1e. Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4
        // + E.
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    fn compute(&mut self) -> Vec<u8> {
        let mut vec = Vec::<u8>::with_capacity(256);
        vec.extend_from_slice(&*self.blocks);

        let num_words_per_block = BLOCK_LEN_BITS / 8;
        let padding = (num_words_per_block - (self.blocks.len() + 9) % num_words_per_block)
            % num_words_per_block;

        // Add 1 as padding as described in section 4a (0x80=0b10000000)
        vec.extend_from_slice(&[0x80u8]);

        for _ in 0..padding {
            vec.push(0u8);
        }

        // Add l, the number of bits in the original message as described in section 4c.
        let l = ((self.blocks.len() as u64 + self.len) * 8).to_be_bytes();
        vec.extend_from_slice(&l);

        // Now process each block as described in section 6.
        for chunk in vec[..].chunks(num_words_per_block) {
            self.process_block(chunk);
        }

        let mut output_vec = Vec::new();
        for &n in self.state.iter() {
            let buf = n.to_be_bytes();
            output_vec.extend_from_slice(&buf);
        }
        output_vec
    }
}

fn to_hex(input: &[u8]) -> String {
    let mut s = String::new();
    for b in input.iter() {
        s.push_str(&*format!("{:02x}", *b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_single_word_to_hex_digits_new() {
        let input: u8 = 0b1010;
        assert_eq!(to_hex(&input.to_ne_bytes()), "0a".to_string());

        let input: u8 = 0b0111;
        assert_eq!(to_hex(&input.to_ne_bytes()), "07".to_string())
    }
    #[test]
    fn test_two_word_to_hex_digits_new() {
        let input: u8 = 0b1010_0001;
        assert_eq!(to_hex(&input.to_ne_bytes()), "a1".to_string())
    }

    #[test]
    fn test_simple() {
        let mut m = Sha1::new();

        let tests = [
            ("The quick brown fox jumps over the lazy dog",
             "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            ("The quick brown fox jumps over the lazy cog",
             "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            ("testing\n", "9801739daae44ec5293d4e1f53d3f4d2d426d91c"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "025ecbd5d70f8fb3c5457cd96bab13fda305dc59"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "4300320394f7ee239bcdce7d3b8bcee173a0cd5c"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "4102d0b82103d2fb1283f0380bf0faed0d3798bb"),
            ("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
             "cef734ba81a024479e09eb5a75b6ddae62e6abf1"),
            ("An archmage often can react poorly to interruption. Please reconsider before it is too late.",
            "46f7305cb842b37f5434f4970e897b8e95894f9a")
        ];

        for &(s, ref h) in tests.iter() {
            let data = s.as_bytes();

            m.reset();
            m.update(data);
            let hh = m.hexdigest();

            assert_eq!(hh.len(), h.len());
            assert_eq!(&*hh, *h);
        }
    }

    #[test]
    fn test_multiple_updates() {
        let mut m = Sha1::new();

        m.reset();
        m.update("The quick brown ".as_bytes());
        m.update("fox jumps over ".as_bytes());
        m.update("the lazy dog".as_bytes());
        let hh = m.hexdigest().to_string();

        let h = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
        assert_eq!(hh.len(), h.len());
        assert_eq!(hh, &*h);
    }
}
