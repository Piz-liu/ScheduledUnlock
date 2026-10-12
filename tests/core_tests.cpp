#include "core.hpp"
#include <stdio.h>
#include <stdlib.h>

static int checks=0;
void Check(bool value,const char* what) {
    ++checks;
    if (!value) { fprintf(stderr,"FAILED: %s\n",what); exit(1); }
}
int main() {
    constexpr uint64_t issued=100000000000;
    su::Request r; r.session=3; r.generation=47; r.nonce=19; r.issued=issued; r.expires=issued+su::kRequestLifetime;
    auto ok=[&](su::Request request,uint64_t now=issued) { return su::Eligible(request,now,3,47,true); };
    Check(ok(r),"valid locked session is eligible");
    Check(ok(r,r.expires-1),"request remains valid immediately before expiry");
    Check(!ok(r,r.expires),"exact expiry is rejected");
    Check(!ok(r,r.expires+1),"expired request is rejected");
    Check(!ok(r,issued-1),"clock rollback/future request is rejected");
    Check(!su::Eligible(r,issued,3,47,false),"unlocked desktop cannot authenticate");
    Check(!su::Eligible(r,issued,4,47,true),"another session cannot use request");
    Check(!su::Eligible(r,issued,3,48,true),"old configuration cannot use request");
    Check(!su::Eligible(r,issued,su::kInvalidSession,47,true),"missing console session is rejected");
    auto bad=r; bad.nonce=0; Check(!ok(bad),"absent nonce is rejected");
    bad=r; bad.generation=0; Check(!ok(bad),"disabled configuration is rejected");
    bad=r; bad.version=2; Check(!ok(bad),"unknown wire version is rejected");
    bad=r; bad.issued=0; Check(!ok(bad),"missing timestamp is rejected");
    bad=r; bad.expires=bad.issued; Check(!ok(bad),"zero lifetime is rejected");
    bad=r; bad.expires=bad.issued-1; Check(!ok(bad),"negative lifetime is rejected");
    bad=r; ++bad.expires; Check(!ok(bad),"overlong lifetime is rejected");
    bad=r; bad.issued=UINT64_MAX-10; bad.expires=5;
    Check(!ok(bad),"timestamp wraparound is rejected");
    printf("%d request eligibility checks passed.\n",checks);
}
