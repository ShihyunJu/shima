#include "shima.cpp"

int main()
{
    shima test;
    uint8_t key[33], data[1024];
    scanf("%s", key);
    scanf("%s", data);
    int len=0, index=0;
    while (data[index]!='\n'&&data[index]!='\r'&&data[index++]!=0) {
        len++;
    }
    test.set(key, data, len);
    printf("KEY : ");
    test.prt_key();
    printf("PLAIN : ");
    test.prt_data();
    test.encrypt();
    printf("ENCRYPT : ");
    test.prt_data();
    test.decrypt();
    printf("DECRYPT : ");
    test.prt_data();
    test.init();
    return 0;
}