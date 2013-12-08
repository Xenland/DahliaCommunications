#include "dahlia.h"

dahlia::dahlia(QWidget *parent)
    : QWidget(parent)
{
    Botan::LibraryInitializer init;

    private_key_pem_global = "";

    //Init main layout
    main_layout = new QVBoxLayout(0);
    this->setLayout(main_layout);

    /*Populate main layout with content*/
    genload_group_box = new QHBoxLayout();
    genload_group_box_widget = new QWidget();
    genload_group_box_widget->setLayout(genload_group_box);
        generate_key_btn = new QPushButton("Generate Key",0);
        genload_group_box->addWidget(generate_key_btn);
        connect(generate_key_btn, SIGNAL(clicked()), this, SLOT(slot_generate_keypair()));

        load_key_btn = new QPushButton("Load Key", 0);
        genload_group_box->addWidget(load_key_btn);


        encrypt_message = new QPushButton("Encrypt Message", 0);
        genload_group_box->addWidget(encrypt_message);
        connect(encrypt_message, SIGNAL(clicked()), this, SLOT(slot_encrypt_message()));

        decrypt_message = new QPushButton("Decrypt Message", 0);
        genload_group_box->addWidget(decrypt_message);
        connect(decrypt_message, SIGNAL(clicked()), this, SLOT(slot_decrypt_message()));

    main_layout->addWidget(genload_group_box_widget);

    gen_load_keys = new QLabel("<h3>Generate or Load Private Key</h3>");
    main_layout->addWidget(gen_load_keys);

    private_key_input = new QTextEdit(0);
    private_key_input->setText("Private Key");
    main_layout->addWidget(private_key_input);

    public_key_input = new QTextEdit(0);
    public_key_input->setText("PublicKey");
    main_layout->addWidget(public_key_input);

    //Compose Message
        compose_message = new QLabel("<h3>Compose Message</h3>");
        main_layout->addWidget(compose_message);

        message_to_send = new QLineEdit();
        message_to_send->setPlaceholderText(QString("Message to send (Max chars 600 letters)"));
        main_layout->addWidget(message_to_send);

        recip_public_key = new QTextEdit(0);
        recip_public_key->setText(QString("Recipient Publickey"));
        main_layout->addWidget(recip_public_key);

        output_encrypted_message = new QTextEdit(0);
        output_encrypted_message->setText(QString("Encrypted Message Output will be generated here"));
        main_layout->addWidget(output_encrypted_message);

    //Decrypt Message
        decrypt_message_label = new QLabel("<h3>Decrypt Message</h3>");
        main_layout->addWidget(decrypt_message_label);

        decrypted_message = new QLineEdit(0);
        decrypted_message->setText(QString("Decrypted Message will be outputed here"));
        main_layout->addWidget(decrypted_message);

        encrypted_message_to_decrypt = new QTextEdit(0);
        encrypted_message_to_decrypt->setText(QString("Paste encrypted message here"));
        main_layout->addWidget(encrypted_message_to_decrypt);
}

//Generate Key Pair
void dahlia::gen_keypair(QByteArray& keypair_output){
    try{
        //Init random number generator
        Botan::AutoSeeded_RNG rng;

        //Generate private RSA key
        Botan::RSA_PrivateKey priv_rsa(rng, 4098 /* bits */);

        //Convert to PEM encoding and output as std::string
        std::string private_key_pem = Botan::PKCS8::PEM_encode(priv_rsa);
        keypair_output.append(QString::fromStdString(private_key_pem));

    }catch(std::exception& e)
    {
        std::cout << "Exception caught: " << e.what() << std::endl;
    }
}

//Convert private to public key
void dahlia::convert_priv_to_public_key(const QByteArray private_key, QByteArray& public_key){
    try{
        //Init Botan stuff
        Botan::AutoSeeded_RNG rng;

        Botan::DataSource_Memory plaintext_private_key_dsmem(QString(private_key).toStdString());
        Botan::PKCS8_PrivateKey * priv_rsa = Botan::PKCS8::load_key(plaintext_private_key_dsmem, rng, "");
        Botan::RSA_PrivateKey botan_rsa_key = Botan::RSA_PrivateKey(priv_rsa->algorithm_identifier(), priv_rsa->pkcs8_private_key(), rng);

        public_key = QString::fromStdString(Botan::X509::PEM_encode(botan_rsa_key)).toUtf8();
    }catch(std::exception& e)
    {
        std::cout << "(dahlia::convert_priv_to_public_key) Exception caught: " << e.what() << std::endl;
    }
}

//SLOT: generate key pair
void dahlia::slot_generate_keypair(){
    QByteArray keypair_output_bytearray = QByteArray();
    gen_keypair(keypair_output_bytearray);

    QByteArray public_key = QByteArray();
    convert_priv_to_public_key(keypair_output_bytearray, public_key);

    //Define private key internally.
    private_key_pem_global = keypair_output_bytearray;

    //Display key pair information
        /** Private Key **/
        private_key_input->setText(QString::fromUtf8(private_key_pem_global));

        /** Public Key **/
        public_key_input->setText(QString(public_key));
}

//Encrypt RSA message
void dahlia::encrypt_message_with_rsa(const QByteArray public_key, const QByteArray message_to_encrypt_with_rsa_formula, QByteArray& output_encrypted_message){
    try
    {
        //Init Botan stuff
        Botan::AutoSeeded_RNG rng;

        //Convert public key string to botan public_key format
        Botan::DataSource_Memory plaintext_publickey_dsmem(QString::fromUtf8(public_key).toStdString());
        Botan::Public_Key * recip_publickey = Botan::X509::load_key(plaintext_publickey_dsmem);

        //Init botan encryptor with publickey (EME1(ripemd-160))
        Botan::PK_Encryptor * rsa_enc1 = Botan::get_pk_encryptor(*recip_publickey, "EME1(RIPEMD-160)");

        Botan::byte encrypted_rsa_block[message_to_encrypt_with_rsa_formula.count()];
        for (int i = 0; i < message_to_encrypt_with_rsa_formula.count(); ++i){
            encrypted_rsa_block[i] = message_to_encrypt_with_rsa_formula[i];
        }

        Botan::SecureVector<Botan::byte> rsa_encrypted = rsa_enc1->encrypt(encrypted_rsa_block, sizeof(encrypted_rsa_block), rng);

        //Convert aes_password_cipher_byte to QByteArray
        for (uint i = 0; i < rsa_encrypted.size(); ++i)
        {
            output_encrypted_message[i] = rsa_encrypted[i];
        }
    }
    catch(std::exception& e)
    {
        std::cout << "Exception caught: " << e.what() << std::endl;
    }
}

//SLOT: Encrypt RSA message
void dahlia::slot_encrypt_message(){
    //Init variables for proccess
    QByteArray public_key = QByteArray();
    QByteArray encrypted_message = QByteArray();

    //Populate Input Parameters (where nessecary)
    public_key.clear();
    public_key.append(recip_public_key->toPlainText().toUtf8());
    encrypt_message_with_rsa(public_key, message_to_send->text().toUtf8(), encrypted_message);

    output_encrypted_message->clear();
    output_encrypted_message->append("-----BEGIN DAHLIA MESSAGE-----");
    output_encrypted_message->append(encrypted_message.toBase64());
    output_encrypted_message->append("-----END DAHLIA MESSAGE-----");

}


//Decrypt RSA message
void dahlia::decrypt_message_with_rsa(const QByteArray private_key, const QByteArray message_to_decrypt_with_rsa_formula, QByteArray& output_decrypted_message){
    try{
        //Init Botan stuff
        Botan::AutoSeeded_RNG rng;

        /** Decrypt message with RSA decryption **/
        //Convert string/QByteArray into Botan Private_Key
        std::string key_pemencoded = QString::fromUtf8(private_key).toStdString();
        Botan::DataSource_Memory plaintext_privatekey_dsmem(key_pemencoded);
        Botan::Private_Key * private_rsa_key = Botan::PKCS8::load_key(plaintext_privatekey_dsmem, rng);

        Botan::PK_Decryptor * rsa_dec1 = Botan::get_pk_decryptor(*private_rsa_key, "EME1(RIPEMD-160)");

        Botan::byte encrypted_message[message_to_decrypt_with_rsa_formula.count()];

        for(uint i = 0; i < message_to_decrypt_with_rsa_formula.count(); i++){
            encrypted_message[i] = message_to_decrypt_with_rsa_formula[i];
        }

        Botan::SecureVector<Botan::byte> plaintext = rsa_dec1->decrypt(encrypted_message, sizeof(encrypted_message));

        QByteArray result;
        for (uint i = 0; i < plaintext.size(); i++)
        {
            result[i] = plaintext[i];
        }

        output_decrypted_message = result;

    }catch(std::exception& e)
    {

        const char * exception_char = e.what();
        qDebug() << "EXCEYPTION: " << QByteArray::fromRawData(exception_char, sizeof(exception_char));
        qDebug() << "exception @ decrypt txt message()";
    }

}

//SLOT: Decrypt RSA message
void dahlia::slot_decrypt_message(){
    QByteArray message_decrypted = QByteArray();
    decrypt_message_with_rsa(private_key_pem_global, QByteArray::fromBase64(encrypted_message_to_decrypt->toPlainText().toUtf8()), message_decrypted);

    decrypted_message->setText(QString::fromUtf8(message_decrypted));
}

dahlia::~dahlia()
{

}
