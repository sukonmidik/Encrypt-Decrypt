using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;
namespace Encrypter_Decrypter
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        public static AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        private static string Encrypt(string text, string key, string iv, bool base64, bool hex)
        {
            aes.Padding = PaddingMode.PKCS7;
            byte[] encryptkey = Encoding.UTF8.GetBytes(key);
            byte[] input = Encoding.UTF8.GetBytes(text);
            using (MemoryStream memstrm = new MemoryStream())
            {
                try
                {
                    if (aes.Mode == CipherMode.CBC)
                    {
                        byte[] encryptiv = Encoding.UTF8.GetBytes(iv);
                        using (ICryptoTransform crypto = aes.CreateEncryptor(encryptkey, encryptiv))
                        {
                            using (CryptoStream strm = new CryptoStream(memstrm, crypto, CryptoStreamMode.Write))
                            {
                                strm.Write(input, 0, input.Length);
                                strm.FlushFinalBlock();
                            }
                            if (base64)
                            {
                                return Convert.ToBase64String(memstrm.ToArray());
                            }
                            if (hex)
                            {
                                var hexstring = BitConverter.ToString(memstrm.ToArray());
                                hexstring = hexstring.Replace("-", "");
                                return hexstring;
                            }
                        }
                    }
                    if (aes.Mode == CipherMode.ECB)
                    {
                        using (ICryptoTransform crypto = aes.CreateEncryptor(encryptkey, null))
                        {
                            using (CryptoStream strm = new CryptoStream(memstrm, crypto, CryptoStreamMode.Write))
                            {
                                strm.Write(input, 0, input.Length);
                                strm.FlushFinalBlock();
                            }
                        }
                        if (base64)
                        {
                            return Convert.ToBase64String(memstrm.ToArray());
                        }
                        if (hex)
                        {
                            var hexstring = BitConverter.ToString(memstrm.ToArray());
                            hexstring = hexstring.Replace("-", "");
                            return hexstring;
                        }
                    }
                }
                catch
                {
                    return null;
                }
            }
            return null;
        }
        public static byte[] HexStringToHex(string inputHex)
        {
            var resultantArray = new byte[inputHex.Length / 2];
            for (var i = 0; i < resultantArray.Length; i++)
            {
                resultantArray[i] = Convert.ToByte(inputHex.Substring(i * 2, 2), 16);
            }
            return resultantArray;
        }
        private static string Decrypt(string text, string key, string iv, bool base64, bool hex, bool plaintext, bool hexinput)
        {
            aes.Padding = PaddingMode.PKCS7;
            byte[] encryptkey = Encoding.UTF8.GetBytes(key);
            byte[] input = new byte [text.Length];
            using (MemoryStream memstrm = new MemoryStream())
            {
                try
                {
                    if (!hexinput)
                    {
                        input = Convert.FromBase64String(text);
                    }
                    else if (hexinput)
                    {
                        input = HexStringToHex(text);
                    }
                    if (aes.Mode == CipherMode.ECB)
                    {
                        using (ICryptoTransform crypto = aes.CreateDecryptor(encryptkey, null))
                        {
                            using (CryptoStream strm = new CryptoStream(memstrm, crypto, CryptoStreamMode.Write))
                            {
                                strm.Write(input, 0, input.Length);
                                strm.FlushFinalBlock();
                            }
                        }
                        if (base64)
                        {
                            return Convert.ToBase64String(memstrm.ToArray());
                        }
                        if (hex)
                        {
                            var hexstring = BitConverter.ToString(memstrm.ToArray());
                            hexstring = hexstring.Replace("-", "");
                            return hexstring;
                        }
                        if (plaintext)
                        {
                            string plain = Encoding.UTF8.GetString(memstrm.ToArray());
                            return plain;
                        }
                    }
                    if (aes.Mode == CipherMode.CBC)
                    {
                        byte[] encryptiv = Encoding.UTF8.GetBytes(iv);
                        using (ICryptoTransform crypto = aes.CreateDecryptor(encryptkey, encryptiv))
                        {
                            using (CryptoStream strm = new CryptoStream(memstrm, crypto, CryptoStreamMode.Write))
                            {
                                strm.Write(input, 0, input.Length);
                                strm.FlushFinalBlock();
                            }
                        }
                        if (base64)
                        {
                            return Convert.ToBase64String(memstrm.ToArray());
                        }
                        if (hex)
                        {
                            var hexstring = BitConverter.ToString(memstrm.ToArray());
                            hexstring = hexstring.Replace("-", "");
                            return hexstring;
                        }
                        if (plaintext)
                        {
                            string plain = Encoding.UTF8.GetString(memstrm.ToArray());
                            return plain;
                        }
                    }
                }
                catch
                {
                    string error = "Unable To Decrypt. Make Sure Your Input Format And/Or Cipher Mode Is Correct. Also Make Sure You Are Decrypting With The Same Key / IV Used To Encryot.";
                    return error;
                }
            }
            return null;
        }
        private void button1_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(textBox1.Text))
            {
                MessageBox.Show("Please Enter Text To Be Encrypted.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (comboBox1.SelectedIndex != 0 & comboBox1.SelectedIndex != 1)
            {
                MessageBox.Show("Please Select Cipher Mode.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (comboBox2.SelectedIndex != 0 & comboBox2.SelectedIndex != 1 & comboBox2.SelectedIndex != 2)
            {
                MessageBox.Show("Please Select Key Size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (comboBox1.SelectedIndex == 0 || comboBox1.SelectedIndex == 1)
            {
                if (string.IsNullOrEmpty(textBox3.Text))
                {
                    MessageBox.Show("Please Enter A Key.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            int keyinput = textBox3.Text.Length;
            switch (comboBox2.SelectedIndex)
            {
                case 0:
                    if (keyinput != 16)
                    {
                        MessageBox.Show("Key Length Should Be 16 For 128 Bit Size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    break;
                case 1:
                   if (keyinput != 24)
                    {
                        MessageBox.Show("Key Length Should Be 24 For 192 Bit Size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    break;
                case 2:
                    if (keyinput != 32)
                    {
                        MessageBox.Show("Key Length Should Be 32 For 256 Bit Size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    break;
            }
            if (comboBox1.SelectedIndex == 1)
            {
                int ivinput = textBox4.Text.Length;
                if (string.IsNullOrEmpty(textBox3.Text))
                {
                    MessageBox.Show("Please Enter A Key.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (ivinput != 16)
                {
                    MessageBox.Show("Initialization Vector Length Should Be 16 With AES.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (string.IsNullOrEmpty(textBox4.Text))
                {
                    MessageBox.Show("Please Enter An Initialization Vector.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            if (!radioButton1.Checked & !radioButton2.Checked)
            {
                MessageBox.Show("Please Select Output Format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (radioButton1.Checked)
            {
                if (comboBox1.SelectedIndex == 0)
                {
                   aes.Mode = CipherMode.ECB;
                   textBox2.Text = Encrypt(textBox1.Text, textBox3.Text, null, true, false);
                }
                if (comboBox1.SelectedIndex == 1)
                {
                    aes.Mode = CipherMode.CBC;
                    textBox2.Text = Encrypt(textBox1.Text, textBox3.Text, textBox4.Text, true, false);
                }
            }
            else if (radioButton2.Checked)
            {
                if (comboBox1.SelectedIndex == 0)
                {
                    aes.Mode = CipherMode.ECB;
                    textBox2.Text = Encrypt(textBox1.Text, textBox3.Text, null, false, true);
                }
                if (comboBox1.SelectedIndex == 1)
                {
                    aes.Mode = CipherMode.CBC;
                    textBox2.Text = Encrypt(textBox1.Text, textBox3.Text, textBox4.Text, false, true);
                }
            }
        }
        private void button2_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(textBox8.Text))
            {
                MessageBox.Show("Please Enter Text To Be Decrypted.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (!radioButton6.Checked & !radioButton7.Checked)
            {
                MessageBox.Show("Please Select Input Format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (comboBox4.SelectedIndex != 0 & comboBox4.SelectedIndex != 1)
            {
                MessageBox.Show("Please Select Cipher Mode.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (comboBox3.SelectedIndex != 0 & comboBox3.SelectedIndex != 1 & comboBox3.SelectedIndex != 2)
            {
                MessageBox.Show("Please Select Key Size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (comboBox4.SelectedIndex == 0 || comboBox4.SelectedIndex == 1)
            {
                if (string.IsNullOrEmpty(textBox6.Text))
                {
                    MessageBox.Show("Please Enter A Key.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            int keyinput = textBox6.Text.Length;
            switch (comboBox3.SelectedIndex)
            {
                case 0:
                    if (keyinput != 16)
                    {
                        MessageBox.Show("Key Length Should Be 16 For 128 Bit Size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    break;
                case 1:
                    if (keyinput != 24)
                    {
                        MessageBox.Show("Key Length Should Be 24 For 192 Bit Size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    break;
                case 2:
                    if (keyinput != 32)
                    {
                        MessageBox.Show("Key Length Should Be 32 For 256 Bit Size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    break;
            }
            if (comboBox4.SelectedIndex == 1)
            {
                int ivinput = textBox5.Text.Length;
                if (string.IsNullOrEmpty(textBox6.Text))
                {
                    MessageBox.Show("Please Enter A Key.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (ivinput != 16)
                {
                    MessageBox.Show("Initialization Vector Length Should Be 16 With AES.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (string.IsNullOrEmpty(textBox5.Text))
                {
                    MessageBox.Show("Please Enter An Initialization Vector.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
            if (!radioButton3.Checked & !radioButton4.Checked & !radioButton5.Checked)
            {
                MessageBox.Show("Please Select Output Format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (radioButton4.Checked)
            {
                if (comboBox4.SelectedIndex == 0)
                {
                    aes.Mode = CipherMode.ECB;
                    if (radioButton6.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, null, true, false, false, false);

                    }
                    else if (radioButton7.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, null, true, false, false, true);
                    }
                }
                if (comboBox4.SelectedIndex == 1)
                {
                    aes.Mode = CipherMode.CBC;
                    if (radioButton6.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, textBox5.Text, true, false, false, false);

                    }
                    else if (radioButton7.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, textBox5.Text, true, false, false, true);
                    }
                }
            }
            else if (radioButton3.Checked)
            {
                if (comboBox4.SelectedIndex == 0)
                {
                    aes.Mode = CipherMode.ECB;
                    if (radioButton6.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, null, false, true, false, false);
                    }
                    else if (radioButton7.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, null, false, true, false, true);
                    }
                }
                if (comboBox4.SelectedIndex == 1)
                {
                    aes.Mode = CipherMode.CBC;
                    if (radioButton6.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, textBox5.Text, false, true, false, false);
                    }
                    else if (radioButton7.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, textBox5.Text, false, true, false, true);
                    }
                }
            }
            else if (radioButton5.Checked)
            {
                if (comboBox4.SelectedIndex == 0)
                {
                    aes.Mode = CipherMode.ECB;
                    if (radioButton6.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, null, false, false, true, false);
                    }
                    else if (radioButton7.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, null, false, false, true, true);
                    }
                }
                if (comboBox4.SelectedIndex == 1)
                {
                    aes.Mode = CipherMode.CBC;
                    if (radioButton6.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, textBox5.Text, false, false, true, false);
                    }
                    else if (radioButton7.Checked)
                    {
                        textBox7.Text = Decrypt(textBox8.Text, textBox6.Text, textBox5.Text, false, false, true, true);
                    }
                }
            }       
        }
    }
}
