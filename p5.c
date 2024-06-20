#include <stdio.h>

// Initial Permutation table
int IP[] = {2, 6, 3, 1, 4, 8, 5, 7};

// Inverse Initial Permutation table
int IP_inverse[] = {4, 1, 3, 5, 7, 2, 8, 6};

// S-boxes
int S0[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 3, 2}
};

int S1[4][4] = {
    {0, 1, 2, 3},
    {2, 0, 1, 3},
    {3, 0, 1, 0},
    {2, 1, 0, 3}
};

// P4 permutation table
int P4[] = {2, 4, 3, 1};

// Initial Permutation function
int initial_permutation(int plaintext) {
    int result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((plaintext >> (8 - IP[i])) & 1) << (7 - i);
    }
    return result;
}

// Inverse Initial Permutation function
int inverse_initial_permutation(int ciphertext) {
    int result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((ciphertext >> (8 - IP_inverse[i])) & 1) << (7 - i);
    }
    return result;
}

// S-box substitution function
int s_box_substitution(int value, int s_box[4][4]) {
    int row = ((value & 0b1000) >> 2) | (value & 0b0001);
    int col = (value & 0b0110) >> 1;
    return s_box[row][col];
}

// Function to perform f_k (Feistel function)
int f_k(int half, int subkey) {
    // Expansion/Permutation
    int expanded_half = ((half & 0b1000) << 3) | ((half & 0b0100) << 1) | ((half & 0b0010) << 1) | ((half & 0b0001) << 3);
    int temp = expanded_half ^ subkey;
    
    // S-box substitution
    int left = s_box_substitution(temp >> 4, S0);
    int right = s_box_substitution(temp & 0x0F, S1);
    
    // Combine S-box results and apply P4 permutation
    int combined = (left << 2) | right;
    int permuted = 0;
    for (int i = 0; i < 4; i++) {
        permuted |= ((combined >> (4 - P4[i])) & 1) << (3 - i);
    }
    return permuted;
}

// Feistel cipher function
int feistel_cipher(int plaintext, int key1, int key2) {
    // Apply initial permutation
    int permuted = initial_permutation(plaintext);
    
    // Split into left and right halves
    int left = permuted >> 4;
    int right = permuted & 0x0F;
    
    // First round of Feistel function with key1
    int temp = right;
    right = left ^ f_k(right, key1);
    left = temp;
    
    // Second round of Feistel function with key2
    temp = right;
    right = left ^ f_k(right, key2);
    left = temp;
    
    // Combine halves and apply inverse initial permutation
    int combined = (right << 4) | left;
    return inverse_initial_permutation(combined);
}

// Function to convert a hexadecimal value to binary and print it
void print_binary(unsigned int value) {
    int i;
    // Print each bit of the value from left to right (MSB to LSB)
    for (i = sizeof(int) * 8 - 1; i >= 0; i--) {
        printf("%d", (value >> i) & 1); // Shift and mask to extract each bit
    }
    printf("\n");
}
int main() {
    unsigned int plaintext;
    unsigned int key1, key2;

    // Input plaintext from user
    printf("Enter the plaintext (8-bit hexadecimal): ");
    scanf("%x", &plaintext);

    // Input keys from user
    printf("Enter the first subkey (8-bit hexadecimal): ");
    scanf("%x", &key1);
    printf("Enter the second subkey (8-bit hexadecimal): ");
    scanf("%x", &key2);

    // Print plain text in both hexadecimal and binary format
    printf("Plain Text (Hex): %02x\n", plaintext);
    printf("Plain Text (Binary): ");
    print_binary(plaintext);

    // Encrypt the plaintext
    unsigned int ciphertext = feistel_cipher(plaintext, key1, key2);

    // Print cipher text in both hexadecimal and binary format
    printf("Cipher Text (Hex): %02x\n", ciphertext);
    printf("Cipher Text (Binary): ");
    print_binary(ciphertext);

    // Decrypt the ciphertext
    unsigned int decrypted_text = feistel_cipher(ciphertext, key2, key1); // Decrypt with keys in reverse order

    // Print decrypted text in both hexadecimal and binary format
    printf("Decrypted Text (Hex): %02x\n", decrypted_text);
    printf("Decrypted Text (Binary): ");
    print_binary(decrypted_text);

    return 0;
}
