using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Windows.Forms;

using KeePass.Forms;
using KeePass.Plugins;
using KeePass.Resources;
using KeePass.UI;

using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Utility;

using Newtonsoft.Json;

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Linq;

namespace Limbo
{
    public sealed class LimboExt : Plugin
    {
        private IPluginHost m_host = null;

        private string[,] graph_config;

        public override void Terminate()
        {
            m_host.CustomConfig.SetString("LMB_CONFIG", JsonConvert.SerializeObject(graph_config));
        }

        public bool IsDeleted(PwEntry entry)
        {
            var RecycleBinUuid = m_host.Database.RecycleBinUuid;
            var currentGroup = entry.ParentGroup;
            while (currentGroup != null)
            {
                if (currentGroup.Uuid.CompareTo(RecycleBinUuid) == 0)
                {
                    return true;
                }
                currentGroup = currentGroup.ParentGroup;
            }
            return false;
        }

        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false;
            m_host = host;

            var old_g_c = m_host.CustomConfig.GetString("LMB_CONFIG", "[]");

            MessageService.ShowInfo(old_g_c);

            try
            {
                graph_config = JsonConvert.DeserializeObject<string[,]>(old_g_c);
            }
            catch(Exception e)
            {
                MessageService.ShowFatal(e);
            }

            return true;
        }


        static Random rd = new Random();
        internal static string CreateString(int stringLength)
        {
            const string allowedChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789";
            char[] chars = new char[stringLength];

            for (int i = 0; i < stringLength; i++)
            {
                chars[i] = allowedChars[rd.Next(0, allowedChars.Length)];
            }

            return new string(chars);
        }



        internal static string ExtractLmbTag(List<string> lst)
        {
            foreach (var tag in lst)
                if (tag.StartsWith("LMB_", StringComparison.Ordinal))
                    return tag;

            return null;
        }
                   

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            if (t != PluginMenuType.Main) return null;

            ToolStripMenuItem tsmi = new ToolStripMenuItem("Limbo");

            ToolStripMenuItem anal = new ToolStripMenuItem("Analyze");
            anal.Click += OnAnalClick;

            tsmi.DropDownItems.Add(anal);

            return tsmi;

        }

        private void OnAnalClick(object sender, EventArgs e)
        {
            PwGroup grp = m_host.Database.RootGroup;
            var entries = grp.GetEntries(true);

            List<Dictionary<string, string>> lst = new List<Dictionary<string, string>>();


            SHA1 sha = new SHA1CryptoServiceProvider();

            foreach (var entry in entries)
            {
                if (entry.Expires || IsDeleted(entry))
                    continue;


                var ex_tag = ExtractLmbTag(entry.Tags);

                if (string.IsNullOrEmpty(ex_tag))
                {
                    ex_tag = "LMB_N" + CreateString(6);
                    entry.AddTag(ex_tag);
                }


                Dictionary<string, string> entry_dict = new Dictionary<string, string>();
                entry_dict.Add("username", entry.Strings.ReadSafe(PwDefs.UserNameField));

                var passwordHash = string.Join("", sha.ComputeHash(entry.Strings.Get(PwDefs.PasswordField).ReadUtf8()).Select(x => x.ToString("x2"))).ToUpperInvariant();

                entry_dict.Add("pass_sha1", passwordHash);
                entry_dict.Add("url", entry.Strings.ReadSafe(PwDefs.UrlField));
                entry_dict.Add("tag", ex_tag);
                entry_dict.Add("creation_date", entry.LastModificationTime.ToString("yyyy-MM-ddTHH\\:mm\\:ss.fffffffzzz"));
                entry_dict.Add("notes", entry.Strings.ReadSafe(PwDefs.NotesField));

                lst.Add(entry_dict);
            }

            var fin = new Dictionary<string, object>
            {
                {"edges", graph_config},
                {"nodes", lst}
            
            };

            var outs = JsonConvert.SerializeObject(fin);

            //MessageService.ShowInfo(outs);

            Process.Start("C:\\Users\\cineq\\repos\\fb-limbo\\limbo-win32-x64\\limbo.exe");

            System.Threading.Thread.Sleep(500);
            SockSend(outs);

        }

        public static void SockSend(string out_msg)
        {

            // Connect to a remote device.  
            try
            {
                // Establish the remote endpoint for the socket.  
                // This example uses port 11000 on the local computer.  
                IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, 2137);

                // Create a TCP/IP  socket.  
                Socket sender = new Socket(ipAddress.AddressFamily,
                    SocketType.Stream, ProtocolType.Tcp);

                // Connect the socket to the remote endpoint. Catch any errors.  
                try
                {
                    sender.Connect(remoteEP);

                    Console.WriteLine("Socket connected to {0}",
                        sender.RemoteEndPoint.ToString());

                    // Encode the data string into a byte array.  
                    byte[] msg = Encoding.ASCII.GetBytes(out_msg);

                    // Send the data through the socket.  
                    int bytesSent = sender.Send(msg);

                   
                    sender.Shutdown(SocketShutdown.Both);
                    sender.Close();

                }
                catch (ArgumentNullException ane)
                {
                    MessageService.ShowFatal("ArgumentNullException : {0}" + ane);
                }
                catch (SocketException se)
                {
                    MessageService.ShowFatal("SocketException : {0}" + se);
                }
                catch (Exception e)
                {
                    MessageService.ShowFatal("Unexpected exception : {0}" + e);
                }


            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }
    }
}
