#include "linkweight.hh"

#include <iostream>
#include <cassert>

namespace vigil
{
    
inline
void 
linkweight::setInfinity(uint64_t inf)
{
    infinity = inf;
}

inline
bool
linkweight::isInfinity() const
{
    return infinity > 0;
}

inline
uint64_t 
linkweight::Infinity() const
{
    return infinity;
}

inline
uint64_t 
linkweight::Value() const
{
    return value;
}


inline
linkweight&
linkweight::operator = (uint64_t v)
{
    infinity = 0;
    value = v;
    return *this;
}

inline
linkweight&
linkweight::operator = (const linkweight& w)
{
    infinity = w.infinity;
    value = w.value;
    return *this;
}

inline
linkweight
linkweight::operator ++ ()
{
    assert(value < MAX_INT);
    value++;
    return *this;
}

inline
linkweight
linkweight::operator -- ()
{
    assert(value > 0);
    value--;
    return *this;
}

inline
linkweight
linkweight::operator += (const linkweight& w)
{    
    assert(infinity + w.infinity >= infinity);
    assert(value + w.value >= value);
    
    infinity += w.infinity;
    value += w.value;
    return *this;
}

inline
linkweight
linkweight::operator -= (const linkweight& w)
{
    assert(infinity >= w.infinity);
    assert(value >= w.value);
    
    infinity -= w.infinity;
    value -= w.value;
    return *this;
}

inline
linkweight
linkweight::operator + (const linkweight& w)
{
    linkweight r;
    assert(infinity + w.infinity >= infinity);
    assert(value + w.value >= value);
    
    r.infinity = infinity + w.infinity;
    r.value = value + w.value;    
    return r;
}

inline
linkweight
linkweight::operator - (const linkweight& w)
{
    linkweight r;
    assert(infinity >= w.infinity);
    assert(value >= w.value);
    
    r.infinity = infinity - w.infinity;
    r.value = value - w.value;    
    return r;
}

inline
bool 
linkweight::operator >  (const linkweight& w) const
{
    if(infinity != w.infinity) return (infinity > w.infinity);
    return (value > w.value);
}

inline
bool 
linkweight::operator >= (const linkweight& w) const
{
    if(infinity != w.infinity) return (infinity > w.infinity);
    return (value >= w.value);
}

inline
bool 
linkweight::operator <  (const linkweight& w) const
{
    if(infinity != w.infinity) return (infinity < w.infinity);
    return (value < w.value);
}

inline
bool 
linkweight::operator <= (const linkweight& w) const
{
    if(infinity != w.infinity) return (infinity < w.infinity);
    return (value <= w.value);
}

inline
bool 
linkweight::operator == (const linkweight& w) const
{
    if(infinity != w.infinity) return false;
    return (value == w.value);
}

inline
bool 
linkweight::operator != (const linkweight& w) const
{
    if(infinity != w.infinity) return true;
    return (value != w.value);
}

inline
std::string
linkweight::string() const
{
    char  buf[30];
    sprintf(buf, "(%llu,%llu)", infinity, value);
    return std::string(buf);
}

inline
std::ostream&
operator <<(std::ostream& os, const linkweight& w)
{
    os << w.string();
    return os;
}

}
