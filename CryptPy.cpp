#include <boost/python.hpp>
#include <Crypt.h>
#include <vector>

using namespace boost::python;
void aes_encrypt(Crypt *crypt, cs msg, cs key)
{
    std::string tmp;
    crypt->aes_encrypt(msg, key, tmp);
}

BOOST_PYTHON_MODULE(CryptPy)
{
    typedef bool (Crypt::*vc1)(const std::string &, const std::string &);
    typedef bool (Crypt::*vc2)(const std::string &, const std::string &, const std::string &);
    typedef bool (Crypt::*ask1)(const std::string &);
    typedef bool (Crypt::*ask2)(const std::string &, const std::string &);
    typedef std::vector<unsigned char> (Crypt::*ae)(const std::string &, const std::string &);
    typedef std::string (Crypt::*ad)(const std::string &, const std::string &);
    class_<Crypt>("Crypt")
        .def("initialize", &Crypt::initialize)
        .def("terminate", &Crypt::terminate)
        .def("clear_string", &Crypt::clear_string)
        .def("load_private_key", &Crypt::load_private_key)
        .def("add_cert", &Crypt::add_cert)
        .def("rem_cert", &Crypt::rem_cert)
        .def("encrypt", &Crypt::encrypt)
        .def("decrypt", &Crypt::decrypt)
        .def("sign", &Crypt::sign)
        .def("verify", &Crypt::verify)
        .def<vc1>("verify_cert", &Crypt::verify_cert)
        .def<vc2>("verify_cert", &Crypt::verify_cert)
        .def("load_my_cert", &Crypt::load_my_cert)
        .def("stringify_cert", &Crypt::stringify_cert)
        .def("aes_gen_key", &Crypt::aes_gen_key)
        .def<ask1>("aes_save_key", &Crypt::aes_save_key)
        .def<ask2>("aes_save_key", &Crypt::aes_save_key)
        .def("aes_del_key", &Crypt::aes_del_key)
        .def("aes_encrypt", &aes_encrypt)
        //            .def<ad>("aes_decrypt", &Crypt::aes_decrypt)
        .def("aes_exist_key", &Crypt::aes_exist_key)
        .def("aes_get_key", &Crypt::aes_get_key);
}
