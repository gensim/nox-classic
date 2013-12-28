#ifndef LINK_WEIGHT_HH
#define LINK_WEIGHT_HH 1

#include <inttypes.h>
#include <string>
#include <stdio.h>

namespace vigil
{
    
class Linkweight
{
public:
    static const uint64_t MAX_INT = -1;
    
    Linkweight() : value(0), infinity(0) {}
    Linkweight(uint64_t value_) : value(value_) , infinity(0) {}
    Linkweight(uint64_t value_, bool infinity_) : value(value_) , infinity(infinity_) {}
    Linkweight(const Linkweight& w) : value(w.value) , infinity(w.infinity) {}
    
    void setInfinity(uint64_t);
    bool isInfinity() const;
    uint64_t Infinity() const;
    uint64_t Value() const;
    
    Linkweight& operator = (uint64_t);
    Linkweight& operator = (const Linkweight&);
    
    Linkweight operator ++ ();
    Linkweight operator -- ();
    Linkweight operator += (const Linkweight&);
    Linkweight operator -= (const Linkweight&);
    Linkweight operator + (const Linkweight&);
    Linkweight operator - (const Linkweight&); 
    
    bool operator >  (const Linkweight&) const;
    bool operator >= (const Linkweight&) const;
    bool operator <  (const Linkweight&) const;
    bool operator <= (const Linkweight&) const;
    bool operator == (const Linkweight&) const;
    bool operator != (const Linkweight&) const;
    
    std::string string();
    
private:
    uint64_t value;
    uint64_t infinity;    
};

}

#endif  /* linkweight.hh */