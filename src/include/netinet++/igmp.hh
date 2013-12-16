//
// igmp v2 header
// ------------------------------------------------------
// |  Type  |  Max Resp Time  |         Checksum        |
// ------------------------------------------------------
// |                  Group Address                     |
// ------------------------------------------------------
//
// igmp v3 query header
// ------------------------------------------------------------------
// |  Type = 0x11 |  Max Resp Time  |            Checksum           |
// ------------------------------------------------------------------
// |                        Group Address                           |
// ------------------------------------------------------------------
// | Resv |S| QRV |       QQIC      |   Number of Source (N)        |
// ------------------------------------------------------------------
// |                        Source Address [1]                      |
// |                        Source Address [2]                      |
// |                               .                                |
// |                               .                                |
// |                               .                                |
// |                        Source Address [N]                      |
// ------------------------------------------------------------------
//
// igmp v3 report header
// ------------------------------------------------------------------
// |  Type = 0x22 |    Reserved     |            Checksum           |
// ------------------------------------------------------------------
// |           Reserved             |  Number of Group Records (M)  |
// ------------------------------------------------------------------
// |                         Group Record [1]                       |
// ------------------------------------------------------------------
// |                         Group Record [2]                       |
// ------------------------------------------------------------------
// |                           .                                    |
// |                           .                                    |
// |                           .                                    |
// ------------------------------------------------------------------
// |                         Group Record [M]                       |
// ------------------------------------------------------------------
//
// igmp v3 group record
// ------------------------------------------------------------------
// |  Record Type  |  Aux Data Len  |     Number of Source (N)      |
// ------------------------------------------------------------------
// |                       Multicast Address                        |
// ------------------------------------------------------------------
// |                        Source Address [1]                      |
// |                        Source Address [2]                      |
// |                               .                                |
// |                               .                                |
// |                               .                                |
// |                        Source Address [N]                      |
// ------------------------------------------------------------------
// |                                                                |
// .                                                                .
// .                         Auxiliary Data                         .
// .                                                                .
// |                                                                |
// ------------------------------------------------------------------
//
//

#ifndef IGMP_HH
#define IGMP_HH

#include "ipaddr.hh"

#include <string>
#include <sstream>

namespace vigil {

// TYPE
struct igmp_type {
    static const uint8_t QUERY = 0x11;              /* Membership query         */
    static const uint8_t V1_REPORT = 0x12;          /* Ver. 1 membership report */
    static const uint8_t V2_REPORT = 0x16;          /* Ver. 2 membership report */
    static const uint8_t V3_REPORT = 0x22;          /* Ver. 3 membership report */
    static const uint8_t LEAVE = 0x17;              /* Leave-group message      */   
};

struct igmp_csum
{
    static uint16_t     checksum(void *, size_t);    
};

inline
uint16_t 
igmp_csum::checksum(void * in, size_t size)
{
    register size_t nleft = size;
    const u_short *w = (u_short *) in;
    register u_short answer;
    register int sum = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) 
    { sum += htons(*(u_char *) w << 8); }

    sum = (sum >> 16) + (sum & 0xffff); // add high 16 to low 16
    sum += (sum >> 16); // add carry
    answer = ~sum;
    return answer;
}

//-----------------------------------------------------------------------------
struct igmp
{   
    igmp();
    
    uint16_t    calc_csum();   
    
    std::string string()   const;
    const char* c_string() const;

    // ------------------------------------------------------------------------
    // ------------------------------------------------------------------------
    uint8_t type;               /* Version & Type             */
    uint8_t code;               /* Max resp code              */
    uint16_t csum;              /* IP-stype Checksum          */
    ipaddr group;               /* Group address being report */   

}__attribute__ ((__packed__)); // -- struct igmp v1&v2

inline
igmp::igmp()
{
    type = 0;
    code = 0;
    csum = 0;
}

inline
uint16_t        
igmp::calc_csum()
{
    uint16_t oldsum = csum;
    csum = 0;
    uint16_t newsum = igmp_csum::checksum(this, sizeof(igmp));
    csum = oldsum;
    return newsum;
}

inline
std::string 
igmp::string() const
{
    std::ostringstream o;

    o << "[(" << group.string() << ")"
      << " type:" << (int)type
      << " code:" << (int)code
      << " sum:" << (int)csum
      << "]";

    return o.str();
}

inline
const char*
igmp::c_string() const
{
    static char buf[1500];
    ::strncpy(buf,this->string().c_str(), 1500);
    return buf; 
}

inline
std::ostream&
operator <<(std::ostream& os,const igmp& igmph)
{
    os << igmph.string();
    return os;
}

//-----------------------------------------------------------------------------

struct igmpv3_query
{ 
    igmpv3_query();
    
    static uint8_t cal_code(const timeval& tv);
    static timeval cal_code_time(const uint8_t c);
    static uint8_t cal_sqrv(const uint8_t qrv, const bool s);        
    uint16_t    calc_csum();   
    
    std::string string()   const;
    const char* c_string() const;
    
    // SQRV
    static const uint8_t SFLAG = 0x08;
    static const uint8_t QRV_MASK = (uint8_t)(~0xF8);
    
    uint8_t type;               /* Type                              */
    uint8_t code;               /* Max resp code                     */
    uint16_t csum;              /* IP-stype Checksum                 */
    ipaddr group;               /* Group address being report        */
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t resv:4;             /* Reserved                          */
    uint8_t sqrv:4;             /* Suppress router-side processing   */
                                /* and Querier's robustness variable */
#else
    uint8_t sqrv:4;             /* Suppress router-side processing   */
                                /* and Querier's robustness variable */
    uint8_t resv:4;             /* Reserved                          */
#endif
    uint8_t qqic;               /* Querier's query interval code     */
    uint16_t numsrc;            /* Number of sources (N)             */
    ipaddr sources[0];          /* Source address[1~N]               */ 
    
}__attribute__ ((__packed__)); // -- struct igmpv3_query

inline
igmpv3_query::igmpv3_query()
{
    type = igmp_type::QUERY;
    code = 0;
    csum = 0;
    resv = 0;
    sqrv = 0;
    qqic = 0;
    numsrc = 0;
}

inline
uint8_t 
igmpv3_query::cal_code(const timeval& tv)
{
    uint16_t t = tv.tv_sec * 10 + (uint16_t)(tv.tv_usec/100000);
    if(t < 128) return (uint8_t)t;
    t &= 0x7FFF;
    
    uint8_t exp = 15;
    while((t & (0x1<< exp)) == 0) exp--;
    return (0x80 | ((exp-7) << 4) |((t>>(exp-4)) & 0x0F));
}

inline
timeval
igmpv3_query::cal_code_time(const uint8_t c)
{
    uint16_t m;
    timeval tv;
    if(c < 128) {
       m = c;
    } else {
       m = ((uint16_t)((c & 0xF) | 0x10)) << (((c>>4)&0x7)+3);        
    }
    tv.tv_sec = m/10;
    tv.tv_usec = (m-(tv.tv_sec*10)) * 100000;
    return tv;
}

inline
uint8_t 
igmpv3_query::cal_sqrv(const uint8_t qrv, const bool s)
{    
    return ((qrv > 7) ? 0 : qrv) | ((s) ? SFLAG : 0);
}

inline
uint16_t        
igmpv3_query::calc_csum()
{
    uint16_t oldsum = csum;
    csum = 0;
    uint16_t newsum = igmp_csum::checksum(this, sizeof(igmpv3_query)+ntohs(numsrc)*4);
    csum = oldsum;
    return newsum;
}

inline
std::string 
igmpv3_query::string() const
{
    const timeval tv1 = cal_code_time(code);
    const timeval tv2 = cal_code_time(qqic);
    std::ostringstream o;

    o << "[(" << group.string() << ")"
      << " type:" << (int)type
      << " code:" << (int)code << "(sec=" << (int)tv1.tv_sec << ", usec=" << (int)tv1.tv_usec << ")"
      << " sum:" << (int)csum
      << " sqrv:" << (int)sqrv
      << " qqic:" << (int)qqic << "(sec=" << (int)tv2.tv_sec << ", usec=" << (int)tv2.tv_usec << ")"
      << " numsrc:" << (int)numsrc;
    for(int i=0; i < ntohs(numsrc); i++) {
        o << " source[" << i <<"]:" << sources[i];
    }
    o << "]";

    return o.str();
}

inline
const char*
igmpv3_query::c_string() const
{
    static char buf[1500];
    ::strncpy(buf,this->string().c_str(), 1500);
    return buf; 
}

inline
std::ostream&
operator <<(std::ostream& os, const igmpv3_query& igmpv3h)
{
    os << igmpv3h.string();
    return os;
}

//-----------------------------------------------------------------------------
struct igmpv3_record_type
{
    static const uint8_t IS_IN = 0x01;
    static const uint8_t IS_EX = 0x02;
    static const uint8_t TO_IN = 0x03;
    static const uint8_t TO_EX = 0x04;
    static const uint8_t ALLOW = 0x05;
    static const uint8_t BLOCK = 0x06;
};

struct igmpv3_record
{    
    igmpv3_record();
    
    const uint16_t size() ;
    uint8_t* next();
    uint8_t* auxdata();
    
    std::string string()   const;
    const char* c_string() const;
    
    uint8_t type;
    uint8_t datalen;
    uint16_t numsrc;
    ipaddr group;
    ipaddr sources[0];   
    
}__attribute__ ((__packed__)); // -- struct igmpv3_record

inline
igmpv3_record::igmpv3_record()
{
    type = 0;
    datalen = 0;
    numsrc = 0;
}

inline
const uint16_t 
igmpv3_record::size()
{
    return sizeof(igmpv3_record) + (ntohs(numsrc) * 4) + (datalen*4);
}

inline
uint8_t* 
igmpv3_record::next()
{
    return (((uint8_t*)this) + size());
}

inline
uint8_t* 
igmpv3_record::auxdata()
{
    if(datalen == 0) return NULL;
    return (next() - (datalen*4));
}

inline
std::string 
igmpv3_record::string() const
{
    std::ostringstream o;

    o << "[(" << group.string() << ")"
      << " type:" << (int)type
      << " datalen:" << (int)datalen
      << " numsrc:" << (int)numsrc;
    for(uint16_t i=0; i < ntohs(numsrc); i++) {
        o << " source[" << i <<"]:" << sources[i];
    }
    o << "]";

    return o.str();
}

inline
const char*
igmpv3_record::c_string() const
{
    static char buf[1500];
    ::strncpy(buf,this->string().c_str(), 1500);
    return buf; 
}

inline
std::ostream&
operator <<(std::ostream& os, const igmpv3_record& igmpv3h)
{
    os << igmpv3h.string();
    return os;
}

struct igmpv3_report
{    
    igmpv3_report();
    
    uint16_t    calc_csum();   
    
    std::string string()   const;
    const char* c_string() const;
    
    // SQRV
    static const uint8_t SFLAG = 0x08;
    static const uint8_t QRV_MASK = (uint8_t)(~0xF8);
    
    uint8_t type;               /* Type                        */
    uint8_t resv8;              /* Reserved                    */
    uint16_t csum;              /* IP-stype Checksum           */
    uint16_t resv16;            /* Reserved                    */
    uint16_t numrec;            /* Number of Group Records (M) */
    igmpv3_record record[0];    /* Group Record[1~M]           */
    
}__attribute__ ((__packed__)); // -- struct igmpv3_report

inline
igmpv3_report::igmpv3_report()
{
    type = igmp_type::V3_REPORT;
    csum = 0;
    numrec = 0;
}

inline
uint16_t 
igmpv3_report::calc_csum()
{
    uint16_t oldsum = csum;
    csum = 0;
    size_t s = sizeof(igmpv3_report);
    igmpv3_record* r = (igmpv3_record*) &record[0];
    for(uint16_t i = 0; i < ntohs(numrec); i++, r = (igmpv3_record*)r->next()) {
        s += r->size();
    }
    uint16_t newsum = igmp_csum::checksum(this, s);
    csum = oldsum;
    return newsum;
}

inline
std::string 
igmpv3_report::string() const
{
    std::ostringstream o;

    o << "[type:" << (int)type
      << " sum:" << (int)csum
      << " numrec:" << (int)numrec;
    igmpv3_record* r = (igmpv3_record*) &record[0];
    for(uint16_t i=0; i < ntohs(numrec); i++, r = (igmpv3_record*)r->next()) {
        o << " record[" << i <<"]:" << r->string();
    }
    o << "]";

    return o.str();
}

inline
const char*
igmpv3_report::c_string() const
{
    static char buf[1500];
    ::strncpy(buf,this->string().c_str(), 1500);
    return buf; 
}

inline
std::ostream&
operator <<(std::ostream& os, const igmpv3_report& igmpv3h)
{
    os << igmpv3h.string();
    return os;
}

}

#endif  // #ifndef IGMP_HH
