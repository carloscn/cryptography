.PHONY: clean

SOURCE = $(wildcard *.c)
TARGET = cms_tool
LD = -lssl -lcrypto

$(TARGET):
	$(CC) -o $@ $(SOURCE) $(LD)

clean:
	$(RM) -rf ${TARGET} *.o

distclean:
	make clean
	$(RM) -rf *.key *.crt *.csr *.txt *.bin

server.crt:
	openssl genrsa -out ca.key 2048
	openssl req -new -x509 -key ca.key -out ca.crt -days 365
	openssl genrsa -out server.key 2048
	openssl req -new -key server.key -out server.csr
	openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt -days 36
	openssl verify -verbose -CAfile ca.crt server.crt

sign: ${TARGET}
	echo "test msg!" > msg.txt
	-@ln -s keys/key_pass.txt .
	./cms_tool sign msg.txt ./keys/IMG1_1_sha256_2048_65537_v3_usr_crt.pem ./keys/IMG1_1_sha256_2048_65537_v3_usr_key.pem signed_file.bin

verify: signed_file.bin
	./cms_tool verify msg.txt ./keys/IMG1_1_sha256_2048_65537_v3_usr_crt.pem ./keys/tmpca.cer signed_file.bin
