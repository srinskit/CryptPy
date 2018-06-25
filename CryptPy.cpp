#include <boost/python.hpp>
#include <Crypt.h>
#include <vector>

namespace bp = boost::python;

bool aes_encrypt(Crypt *crypt, const bp::list &msg_l, cs key, bp::list &dump_l) {
    std::string dump, msg;
    for (int i = 0; i < bp::len(msg_l); ++i)
        msg.append(1, (char) bp::extract<uint8_t>(msg_l[i]));
    if (!crypt->aes_encrypt(msg, key, dump))return false;
    for (auto &ch: dump)
        dump_l.append((uint8_t) ch);
    return true;
}

bool aes_decrypt(Crypt *crypt, const bp::list &dump_l, cs key, bp::list &msg_l) {
    std::string dump, msg;
    for (int i = 0; i < bp::len(dump_l); ++i)
        dump.append(1, (char) bp::extract<uint8_t>(dump_l[i]));
    if (!crypt->aes_decrypt(dump, key, msg))return false;
    for (auto &ch: msg)
        msg_l.append((uint8_t) ch);
    return true;
}

BOOST_PYTHON_MODULE (libCryptPy) {
    typedef bool (Crypt::*vc1)(cs &, cs &);
    typedef bool (Crypt::*vc2)(cs &, cs &, cs &);
    typedef bool (Crypt::*ask1)(cs &);
    typedef bool (Crypt::*ask2)(cs &, cs &);
    bp::class_<Crypt>("Crypt")
            .def("initialize", &Crypt::initialize)
            .def("terminate", &Crypt::terminate)
            .def("load_private_key", &Crypt::load_private_key)
            .def("add_cert", &Crypt::add_cert)
            .def("rem_cert", &Crypt::rem_cert)
//            .def("encrypt", &Crypt::encrypt)
//            .def("decrypt", &Crypt::decrypt)
//            .def("sign", &Crypt::sign)
            .def("verify", &Crypt::verify)
            .def<vc1>("verify_cert", &Crypt::verify_cert)
            .def<vc2>("verify_cert", &Crypt::verify_cert)
            .def("load_my_cert", &Crypt::load_my_cert)
            .def("stringify_cert", &Crypt::stringify_cert)
//            .def("aes_gen_key", &Crypt::aes_gen_key)
            .def<ask1>("aes_save_key", &Crypt::aes_save_key)
            .def<ask2>("aes_save_key", &Crypt::aes_save_key)
            .def("aes_del_key", &Crypt::aes_del_key)
            .def("aes_encrypt", &aes_encrypt)
            .def("aes_decrypt", &aes_decrypt)
            .def("aes_exist_key", &Crypt::aes_exist_key)
            .def("aes_get_key", &Crypt::aes_get_key);
}
