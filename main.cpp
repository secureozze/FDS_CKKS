#pragma warning(disable : 4996)
#include <iostream>
#include <memory>
#include <vector>
#include <iomanip> 

//#include "database.h"
#include <mysql/jdbc.h>
#include "seal/seal.h"

using namespace seal;
using namespace std;

// Specify our connection target and credentials
const string server = "127.0.0.1:3306";
const string username = "root";
const string password = "toor!@";
const string database = "detect";
const string table01 = "past_transaction";
const string table02 = "realtime_transaction";

int main()
{
    sql::Driver* driver; // Create a pointer to a MySQL driver object
    sql::Connection* dbConn; // Create a pointer to a database connection object
    sql::Statement* stmt;   // Create a pointer to a Statement object to hold our SQL commands
    sql::ResultSet* res;    // Create a pointer to a ResultSet object to hold the results of any queries we run
    vector<string> user;



    EncryptionParameters parms(scheme_type::CKKS);


    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys_local();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    // Try to get a driver to use to connect to our DBMS
    try
    {
        driver = get_driver_instance();
    }
    catch (sql::SQLException e)
    {
        cout << "Could not get a database driver. Error message: " << e.what() << endl;
        system("pause");
        exit(1);
    }

    // Try to connect to the DBMS server
    try
    {
        dbConn = driver->connect(server, username, password);
        dbConn->setSchema(database);
    }
    catch (sql::SQLException e)
    {
        cout << "Could not connect to database. Error message: " << e.what() << endl;
        system("pause");
        exit(1);
    }
    stmt = dbConn->createStatement();
    //user ��������
    try
    {
        res = stmt->executeQuery("SELECT * FROM " + table02);

    }
    catch (sql::SQLException e)
    {
        cout << "SQL error. Error message: " << e.what() << endl;
        system("pause");
        exit(1);
    }

    while (res->next()) {
        user.push_back(res->getString(1));
    }
    cout << " (�ǽð� ������) - (���ŵ����� ���) " << endl;

    // user ���� ������ ��������
    for (int i = 0; i < user.size(); i++) {
        string userid = user.at(i);
        try
        {

            //stmt->execute("USE " + database);              // Select which database to use. Notice that we use "execute" to perform a command.
            //res = stmt->executeQuery("INSERT INTO " + table + "(Brand, Model, Power, `Last Used`,`# Times Used`) VALUES('Ferrari','Modena','500','Never',0)");
            res = stmt->executeQuery("SELECT * FROM " + table01 + " where userid='" + userid + "'"); // Perform a query and get the results. Notice that we use "executeQuery" to get results back
            //res = stmt->executeQuery("INSERT INTO test VALUES (?, ? ,? )");

        }
        catch (sql::SQLException e)
        {
            cout << "SQL error. Error message: " << e.what() << endl;
            system("pause");
            exit(1);
        }
        vector<Ciphertext> list;
        while (res->next()) {
            Ciphertext x_encrypted;
            Plaintext x_plain;
            encoder.encode(res->getInt(2), scale, x_plain);
            encryptor.encrypt(x_plain, x_encrypted);

            list.push_back(x_encrypted);
        }

        // �ǽð� ������ �޾ƿ���
        try
        {
            res = stmt->executeQuery("SELECT * FROM " + table02 + " where userid='" + userid + "'");
        }
        catch (sql::SQLException e)
        {
            cout << "SQL error. Error message: " << e.what() << endl;
            system("pause");
            exit(1);
        }
        vector<Ciphertext> list2;
        while (res->next()) {
            Ciphertext y_encrypted;
            Plaintext y_plain;
            encoder.encode(res->getInt(2), scale, y_plain);
            encryptor.encrypt(y_plain, y_encrypted);

            list2.push_back(y_encrypted);
        }

        Plaintext plain;
        encoder.encode(1.0 / list.size(), scale, plain);

        // ���� ������ ��� ����.
        Ciphertext encrypt_sum;
        Plaintext init;
        encoder.encode(0.0, scale, init);
        encryptor.encrypt(init, encrypt_sum);
        for (int i = 0; i < list.size(); i++) {
            evaluator.add(encrypt_sum, list.at(i), encrypt_sum);
        }

        //���� ������ / ������ ����
        Ciphertext encrypt_avgresult;
        Ciphertext encrypt_result;
        evaluator.multiply_plain(encrypt_sum, plain, encrypt_avgresult);
        evaluator.relinearize_inplace(encrypt_avgresult, relin_keys);
        evaluator.rescale_to_next_inplace(encrypt_avgresult);
        encrypt_avgresult.scale() = pow(2.0, 40);
        list2.at(0).scale() = pow(2.0, 40);
        parms_id_type last_parms_id = encrypt_avgresult.parms_id();
        evaluator.mod_switch_to_inplace(list2.at(0), last_parms_id);
        //�ǽð� ������ - ���� ������
        evaluator.sub(list2.at(0), encrypt_avgresult, encrypt_result);


        ////////////////////////   ���   /////////////////////////
        cout << "============== " << userid << " ==============" << endl;

        // �ǽð� ���
        Plaintext realtime_amout;
        decryptor.decrypt(list2.at(0), realtime_amout);
        vector<double> realtime_amount_result;
        encoder.decode(realtime_amout, realtime_amount_result);
        cout << "*** �ǽð� �ŷ� �ݾ�";
        print_vector(realtime_amount_result, 1, 2);


        // ���� �ݾ� �ǽð� �ŷ� �ݾ� - ���� �ŷ� �ݾ� ��հ�� ���
        Plaintext plain_result;
        Plaintext avg_result;
        decryptor.decrypt(encrypt_result, plain_result);
        vector<double> result;
        encoder.decode(plain_result, result);
        cout << "*** Ž�� ���� �ݾ� (�ǽð� �ŷ� �ݾ� - ���� �ŷ� �ݾ� ���)";
        print_vector(result, 1, 2);


        cout << "*** " << userid << "�� �ŷ� ����" << endl << endl;
        decryptor.decrypt(encrypt_avgresult, avg_result);
        vector<double> avg;
        encoder.decode(avg_result, avg);
        cout << "[���� �ŷ� ����]" << endl;
        cout << "�ŷ��ݾ� <" << avg.at(0) * 2 << endl << endl;

        cout << "[���� �ŷ� ����]" << endl;
        cout << fixed << setprecision(2) << avg.at(0) * 2 << " <= �ŷ��ݾ� < " << avg.at(0) * 3 << endl << endl;

        cout << "[���� �ŷ� ����]" << endl;
        cout << avg.at(0) * 3 << " <= �ŷ��ݾ�" << endl << endl << endl;

        if (result.at(0) >= avg.at(0) * 3) {
            cout << "*** ���� ***" << endl;
            cout << "������ Ȱ���� �³���? �´ٸ� YES�� �����ֽð� �ŷ����� ������ ���� ���������� ���ּ���" << endl << endl << endl;
        }
        else if (result.at(0) >= avg.at(0) * 2) {
            cout << "** ���� **" << endl;
            cout << "������ Ȱ���� �³���? �´ٸ� Yes�� �����ּ���" << endl << endl << endl;
        }
        else {
            cout << "�ŷ��� �Ϸ�Ǿ����ϴ�." << endl << endl << endl;
        }
    }

    delete res;
    delete stmt;
    delete dbConn;

    system("pause");
    return 0;
}