
//create a stack > 400 entries high and then crash on a write.
//<rdar://problem/6447386> mac_cw: if crashing thread stack is sufficiently long, don't mark as security

static int count = 0;
void f1 () {
    if (count < 410) {
        count++;
        f1();
    } else {
        char * ptr = (char*)0x88888888;
        *ptr = 0;
    }
    
}
int main() {
    f1();
}