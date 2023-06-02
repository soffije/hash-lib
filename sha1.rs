extern crate crypto;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use std::time::Instant;

const BLOCK_SIZE: usize = 64;

fn pad_message(message: &[u8]) -> Vec<u8> {
    let message_len = message.len();
    let bit_len = (message_len as u64) * 8;
    let mut padded = Vec::from(message);

    // Додаємо одну '1' бітову одиницю
    padded.push(0x80);

    // Додаємо '0' біти до того моменту, коли довжина повідомлення у бітах буде відповідати 448 (mod 512)
    while (padded.len() % BLOCK_SIZE) != (BLOCK_SIZE - 8) {
        padded.push(0);
    }

    // Додаємо оригінальну довжину повідомлення у бітах як 64-бітне ціле число у порядку big-endian
    padded.extend(&[(bit_len >> 56) as u8]);
    padded.extend(&[(bit_len >> 48) as u8]);
    padded.extend(&[(bit_len >> 40) as u8]);
    padded.extend(&[(bit_len >> 32) as u8]);
    padded.extend(&[(bit_len >> 24) as u8]);
    padded.extend(&[(bit_len >> 16) as u8]);
    padded.extend(&[(bit_len >> 8) as u8]);
    padded.extend(&[(bit_len & 0xff) as u8]);

    padded
}

fn hash_sha1(message: &[u8]) -> [u8; 20] {
    let padded_message = pad_message(message);
    let block_count = padded_message.len() / BLOCK_SIZE;

    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    for i in 0..block_count {
        let block = &padded_message[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
        let mut words = [0u32; 80];

        // Ініціалізуємо перші 16 слів даними з блоку
        for j in 0..16 {
            let offset = j * 4;
            words[j] = ((block[offset] as u32) << 24)
                | ((block[offset + 1] as u32) << 16)
                | ((block[offset + 2] as u32) << 8)
                | block[offset + 3] as u32;
        }

        // Розширюємо решту слів
        for j in 16..80 {
            let w = words[j - 3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16];
            words[j] = w.rotate_left(1);
        }

        // Ініціалізуємо значення хешу для цього блоку
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        // Головний цикл
        for j in 0..80 {
            let f;
            let k;
            if j < 20 {
                f = (b & c) | ((!b) & d);
                k = 0x5A827999;
            } else if j < 40 {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if j < 60 {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(words[j])
                .wrapping_add(k);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Оновлюємо значення хешу для цього блоку
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0] = (h0 >> 24) as u8;
    result[1] = (h0 >> 16) as u8;
    result[2] = (h0 >> 8) as u8;
    result[3] = h0 as u8;
    result[4] = (h1 >> 24) as u8;
    result[5] = (h1 >> 16) as u8;
    result[6] = (h1 >> 8) as u8;
    result[7] = h1 as u8;
    result[8] = (h2 >> 24) as u8;
    result[9] = (h2 >> 16) as u8;
    result[10] = (h2 >> 8) as u8;
    result[11] = h2 as u8;
    result[12] = (h3 >> 24) as u8;
    result[13] = (h3 >> 16) as u8;
    result[14] = (h3 >> 8) as u8;
    result[15] = h3 as u8;
    result[16] = (h4 >> 24) as u8;
    result[17] = (h4 >> 16) as u8;
    result[18] = (h4 >> 8) as u8;
    result[19] = h4 as u8;

    result
}

fn main() {
    let message = b"Cryptography";
    println!("Our message: {:?}", String::from_utf8_lossy(message));

    let start_custom = Instant::now();
    let custom_hash = hash_sha1(message);
    let duration_custom = start_custom.elapsed();
    let custom_hash_hex: String = custom_hash.iter().map(|byte| format!("{:02x}", byte)).collect();
    println!("SHA-1 Hash (Custom): {}", custom_hash_hex);
    println!("Execution Time (Custom): {} nanoseconds", duration_custom.as_nanos());

    let start_lib = Instant::now();
    let mut hasher = Sha1::new();
    hasher.input(message);
    let mut library_hash = [0u8; 20];
    hasher.result(&mut library_hash);
    let duration_lib = start_lib.elapsed();
    let library_hash_hex: String = library_hash.iter().map(|byte| format!("{:02x}", byte)).collect();
    println!("SHA-1 Hash (Library): {}", library_hash_hex);
    println!("Execution Time (Library): {} nanoseconds", duration_lib.as_nanos());

    if custom_hash == library_hash {
        println!("Hashes match.");
    } else {
        println!("Hashes do not match.");
    }
}
