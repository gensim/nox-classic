#include "linkweight.hh"

#include <iostream>
#include <cassert>

namespace vigil
{

void 
Linkweight::setInfinity(uint64_t inf)
{
    infinity = inf;
}

bool
Linkweight::isInfinity() const
{
    return infinity > 0;
}

uint64_t 
Linkweight::Infinity() const
{
    return infinity;
}

uint64_t 
Linkweight::Value() const
{
    return value;
}

Linkweight&
Linkweight::operator = (uint64_t v)
{
    infinity = 0;
    value = v;
    return *this;
}

Linkweight&
Linkweight::operator = (const Linkweight& w)
{
    infinity = w.infinity;
    value = w.value;
    return *this;
}

Linkweight
Linkweight::operator ++ ()
{
    assert(value < MAX_INT);
    value++;
    return *this;
}

Linkweight
Linkweight::operator -- ()
{
    assert(value > 0);
    value--;
    return *this;
}

Linkweight
Linkweight::operator += (const Linkweight& w)
{    
    assert(infinity + w.infinity >= infinity);
    assert(value + w.value >= value);
    
    infinity += w.infinity;
    value += w.value;
    return *this;
}

Linkweight
Linkweight::operator -= (const Linkweight& w)
{
    assert(infinity >= w.infinity);
    assert(value >= w.value);
    
    infinity -= w.infinity;
    value -= w.value;
    return *this;
}

Linkweight
Linkweight::operator + (const Linkweight& w)
{
    Linkweight r;
    assert(infinity + w.infinity >= infinity);
    assert(value + w.value >= value);
    
    r.infinity = infinity + w.infinity;
    r.value = value + w.value;    
    return r;
}

Linkweight
Linkweight::operator - (const Linkweight& w)
{
    Linkweight r;
    assert(infinity >= w.infinity);
    assert(value >= w.value);
    
    r.infinity = infinity - w.infinity;
    r.value = value - w.value;    
    return r;
}

bool 
Linkweight::operator >  (const Linkweight& w) const
{
    if(infinity != w.infinity) return (infinity > w.infinity);
    return (value > w.value);
}

bool 
Linkweight::operator >= (const Linkweight& w) const
{
    if(infinity != w.infinity) return (infinity > w.infinity);
    return (value >= w.value);
}

bool 
Linkweight::operator <  (const Linkweight& w) const
{
    if(infinity != w.infinity) return (infinity < w.infinity);
    return (value < w.value);
}

bool 
Linkweight::operator <= (const Linkweight& w) const
{
    if(infinity != w.infinity) return (infinity < w.infinity);
    return (value <= w.value);
}

bool 
Linkweight::operator == (const Linkweight& w) const
{
    if(infinity != w.infinity) return false;
    return (value == w.value);
}

bool 
Linkweight::operator != (const Linkweight& w) const
{
    if(infinity != w.infinity) return true;
    return (value != w.value);
}

std::string
Linkweight::string()
{
    char  buf[30];
    sprintf(buf, "(%llu,%llu)", infinity, value);
    return std::string(buf);
}

std::ostream&
operator <<(std::ostream& os, Linkweight& w)
{
    os << w.string();
    return os;
}

}
