#ifndef WEIGHT_HH
#define WEIGHT_HH 1

#include <iostream>
#include <cassert>
#include <string>

namespace vigil
{
    
class weight
{
public:
    static const uint64_t MAX_INT = -1;
    
    weight() : value(0), infinity(0) {}
    weight(uint64_t value_) : value(value_) , infinity(0) {}
    weight(uint64_t value_, bool infinity_) : value(value_) , infinity(infinity_) {}
    weight(const weight& w) : value(w.value) , infinity(w.infinity) {}
    
    void setInfinity(uint64_t);
    bool isInfinity() const;
    uint64_t Infinity() const;
    uint64_t Value() const;
    
    weight& operator = (uint64_t);
    weight& operator = (const weight&);
    
    weight operator ++ ();
    weight operator -- ();
    weight operator += (const weight&);
    weight operator -= (const weight&);
    weight operator + (const weight&);
    weight operator - (const weight&); 
    
    bool operator >  (const weight&) const;
    bool operator >= (const weight&) const;
    bool operator <  (const weight&) const;
    bool operator <= (const weight&) const;
    bool operator == (const weight&) const;
    bool operator != (const weight&) const;
    
    std::string string() const;
    
private:
    uint64_t value;
    uint64_t infinity;    
};

inline
void 
weight::setInfinity(uint64_t inf)
{
    infinity = inf;
}

inline
bool
weight::isInfinity() const
{
    return infinity > 0;
}

inline
uint64_t 
weight::Infinity() const
{
    return infinity;
}

inline
uint64_t 
weight::Value() const
{
    return value;
}


inline
weight&
weight::operator = (uint64_t v)
{
    infinity = 0;
    value = v;
    return *this;
}

inline
weight&
weight::operator = (const weight& w)
{
    infinity = w.infinity;
    value = w.value;
    return *this;
}

inline
weight
weight::operator ++ ()
{
    assert(value < MAX_INT);
    value++;
    return *this;
}

inline
weight
weight::operator -- ()
{
    assert(value > 0);
    value--;
    return *this;
}

inline
weight
weight::operator += (const weight& w)
{    
    assert(infinity + w.infinity >= infinity);
    assert(value + w.value >= value);
    
    infinity += w.infinity;
    value += w.value;
    return *this;
}

inline
weight
weight::operator -= (const weight& w)
{
    assert(infinity >= w.infinity);
    assert(value >= w.value);
    
    infinity -= w.infinity;
    value -= w.value;
    return *this;
}

inline
weight
weight::operator + (const weight& w)
{
    weight t;
    assert(infinity + w.infinity >= infinity);
    assert(value + w.value >= value);
    
    t.infinity = infinity + w.infinity;
    t.value = value + w.value;    
    return t;
}

inline
weight
weight::operator - (const weight& w)
{
    weight t;
    assert(infinity >= w.infinity);
    assert(value >= w.value);
    
    t.infinity = infinity - w.infinity;
    t.value = value - w.value;    
    return t;
}

inline
bool 
weight::operator >  (const weight& w) const
{
    if(infinity != w.infinity) return (infinity > w.infinity);
    return (value > w.value);
}

inline
bool 
weight::operator >= (const weight& w) const
{
    if(infinity != w.infinity) return (infinity > w.infinity);
    return (value >= w.value);
}

inline
bool 
weight::operator <  (const weight& w) const
{
    if(infinity != w.infinity) return (infinity < w.infinity);
    return (value < w.value);
}

inline
bool 
weight::operator <= (const weight& w) const
{
    if(infinity != w.infinity) return (infinity < w.infinity);
    return (value <= w.value);
}

inline
bool 
weight::operator == (const weight& w) const
{
    if(infinity != w.infinity) return false;
    return (value == w.value);
}

inline
bool 
weight::operator != (const weight& w) const
{
    if(infinity != w.infinity) return true;
    return (value != w.value);
}

inline
std::string
weight::string() const
{
    char  buf[30];
    sprintf(buf, "(%llu,%llu)", infinity, value);
    return std::string(buf);
}

inline
std::ostream&
operator <<(std::ostream& os, const weight& w)
{
    os << w.string();
    return os;
}

}

#endif  /* weight.hh */