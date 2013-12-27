#ifndef linkweight_HH
#define linkweight_HH 1

#include <inttypes.h>
#include <string>
#include <stdio.h>

namespace vigil
{
    
class linkweight
{
public:
    static const uint64_t MAX_INT = -1;
    
    linkweight() : value(0), infinity(0) {}
    linkweight(uint64_t value_) : value(value_) , infinity(0) {}
    linkweight(uint64_t value_, bool infinity_) : value(value_) , infinity(infinity_) {}
    linkweight(const linkweight& w) : value(w.value) , infinity(w.infinity) {}
    
    void setInfinity(uint64_t);
    bool isInfinity() const;
    uint64_t Infinity() const;
    uint64_t Value() const;
    
    linkweight& operator = (uint64_t);
    linkweight& operator = (const linkweight&);
    
    linkweight operator ++ ();
    linkweight operator -- ();
    linkweight operator += (const linkweight&);
    linkweight operator -= (const linkweight&);
    linkweight operator + (const linkweight&);
    linkweight operator - (const linkweight&); 
    
    bool operator >  (const linkweight&) const;
    bool operator >= (const linkweight&) const;
    bool operator <  (const linkweight&) const;
    bool operator <= (const linkweight&) const;
    bool operator == (const linkweight&) const;
    bool operator != (const linkweight&) const;
    
    std::string string() const;
    
private:
    uint64_t value;
    uint64_t infinity;    
};

}

#endif  /* linkweight.hh */