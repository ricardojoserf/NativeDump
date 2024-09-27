#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


// XOR decode function (same as encode because XOR is symmetric)
uint8_t* decode_bytes(uint8_t* encoded_bytes, int encoded_len, char* key_xor, int key_len) {
    uint8_t* decoded_bytes = (uint8_t*)malloc(encoded_len);  // Allocate memory for the decoded bytes
    if (!decoded_bytes) {
        return NULL;  // Check if memory allocation failed
    }

    // XOR each byte of the encoded data with the corresponding byte from the key (cyclically)
    for (int i = 0; i < encoded_len; i++) {
        decoded_bytes[i] = encoded_bytes[i] ^ key_xor[i % key_len];
    }

    return decoded_bytes;
}

// Function to read a file into memory
uint8_t* read_file(const char* filename, int* file_size) {
    FILE* file = NULL;

    // Use fopen_s for safer file opening
    if (fopen_s(&file, filename, "rb") != 0) {
        printf("[-] Error: Could not open file %s\n", filename);
        return NULL;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory to store the file contents
    uint8_t* buffer = (uint8_t*)malloc(*file_size);
    if (!buffer) {
        printf("[-] Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    // Read the file contents into the buffer
    fread(buffer, 1, *file_size, file);
    fclose(file);  // Close the file

    return buffer;
}

// Function to write a buffer to a file
int write_file(const char* filename, uint8_t* data, int data_len) {
    FILE* file = NULL;

    // Use fopen_s for safer file opening
    if (fopen_s(&file, filename, "wb") != 0) {
        printf("[-] Error: Could not open file %s\n", filename);
        return 1;
    }

    // Write the data to the file
    fwrite(data, 1, data_len, file);
    fclose(file);  // Close the file

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("[+] Usage: %s <encoded file> <output file> <xor key>\n", argv[0]);
        return 1;
    }

    const char* input_filename = argv[1];  // Encoded file
    const char* output_filename = argv[2];  // Decoded output file
    char* xor_key = argv[3];  // XOR key provided by the user
    int key_len = strlen(xor_key);  // Length of the XOR key

    // Read the encoded file into memory
    int file_size;
    uint8_t* encoded_data = read_file(input_filename, &file_size);
    if (!encoded_data) {
        return 1;
    }

    // Decode the file using the XOR key
    uint8_t* decoded_data = decode_bytes(encoded_data, file_size, xor_key, key_len);
    if (!decoded_data) {
        free(encoded_data);
        printf("[-] Error: Decoding failed\n");
        return 1;
    }

    // Write the decoded data to the output file
    if (write_file(output_filename, decoded_data, file_size) != 0) {
        free(encoded_data);
        free(decoded_data);
        printf("[-] Error: Writing output file failed\n");
        return 1;
    }

    printf("[+] File decoded successfully and saved to %s\n", output_filename);

    // Free allocated memory
    free(encoded_data);
    free(decoded_data);

    return 0;
}
