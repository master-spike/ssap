#pragma once

#include <functional>
#include <string>

namespace ssap
{

class participant
{
public:
private:
    std::function<int(std::string, std::string)> f_whisper;
    std::function<int(std::string)> f_broadcast;
    std::string m_ss_pub_der;
    std::string m_ss_priv_der;
    std::string m_host_pub_der;
    std::string m_host_priv_der;
};

} // namespace ssap
