#ifndef DAHLIA_H
#define DAHLIA_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QDebug>

#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <memory>

#include <botan/botan.h>
#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/pk_keys.h>
#include <botan/look_pk.h>

class dahlia : public QWidget
{
    Q_OBJECT

public:
    dahlia(QWidget *parent = 0);
    ~dahlia();

private:
    QByteArray private_key_pem_global;

    QVBoxLayout * main_layout;
        QLabel * gen_load_keys;
        QWidget * genload_group_box_widget;
        QHBoxLayout * genload_group_box;
            QPushButton * generate_key_btn;
            QPushButton * load_key_btn;
            QPushButton * encrypt_message;
            QPushButton * decrypt_message;

        QTextEdit * private_key_input;
        QTextEdit * public_key_input;

        QLabel * compose_message;
        QLineEdit * message_to_send;
        QTextEdit * recip_public_key;
        QTextEdit * output_encrypted_message;

        QLabel * decrypt_message_label;
        QLineEdit * decrypted_message;
        QTextEdit * encrypted_message_to_decrypt;

    //Functions
    void gen_keypair(QByteArray& keypair_output);
    void convert_priv_to_public_key(const QByteArray private_key, QByteArray& public_key);
    void encrypt_message_with_rsa(const QByteArray public_key, const QByteArray message_to_encrypt_with_rsa_formula, QByteArray& output_encrypted_message);
    void decrypt_message_with_rsa(const QByteArray private_key, const QByteArray message_to_decrypt_with_rsa_formula, QByteArray& output_decrypted_message);

private slots:
    void slot_generate_keypair();
    void slot_encrypt_message();
    void slot_decrypt_message();
};

#endif // DAHLIA_H
