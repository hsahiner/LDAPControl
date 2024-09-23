using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

public class LDAPControl
{
	private static string _server; // serverr port or domain name
	private static int _port; // 389 
	private static string _bindDn; // LDAP Admin User DN cn=admin,dc=example,dc=com
	private static string _bindPassword; // LDAP Admin Password
	private static string _baseDn; // indicates a search or work unit or subunit ou=subunit,ou=unit,dc=example,dc=com
	public LDAPControl(string server, int port, string bindDn, string bindPassword, string baseDn)
	{
		_server = server ?? "default";
		_port = port;
		_bindDn = bindDn ?? "default";
		_bindPassword = bindPassword ?? "default";
		_baseDn = baseDn ?? "default";
	}

	public static bool AddNewAccount(LdapUserClass user)
	{
		try
		{
			var connection = new LdapConnection();
			
				connection.Connect(_server, _port);
				connection.Bind(_bindDn, _bindPassword);

				string dn = "cn="+user.username+","+ _baseDn;
				LdapAttributeSet attrs = new LdapAttributeSet();

				attrs.Add(new LdapAttribute("objectClass", new string[] { "inetOrgPerson", "organizationalPerson", "person", "top" }));
				attrs.Add(new LdapAttribute("cn", user.cn));
				attrs.Add(new LdapAttribute("uid", user.uid));
				attrs.Add(new LdapAttribute("givenName", user.givenName));
				attrs.Add(new LdapAttribute("sn", user.sn));
				attrs.Add(new LdapAttribute("userPassword", user.userPassword));
				attrs.Add(new LdapAttribute("mail", user.mail));
				attrs.Add(new LdapAttribute("idNumber", user.idNumber));
				attrs.Add(new LdapAttribute("title", user.title));
				attrs.Add(new LdapAttribute("telephoneNumber", user.telephoneNumber));
				attrs.Add(new LdapAttribute("mobile", user.mobile));
				attrs.Add(new LdapAttribute("jobUnit", user.jobUnit));


				var newEntry = new LdapEntry(dn, attrs);
				connection.Add(newEntry);

				Console.WriteLine("New User :"+ user.username);
				return true;
			
		}
		catch (LdapException ex)
		{
			Console.WriteLine("Exception :" +ex.Message);
			return false;
		}
	}

	public static bool ChangePassword(string username, string oldPassword, string newPassword, bool admin=false)
	{		

		try
		{
			var connection = new LdapConnection();

			connection.Connect(_server, _port);
			if (admin)
			{
				connection.Bind(_bindDn, _bindPassword);
			}
			else
			{
				connection.Bind(username, oldPassword);
			}
			

			string userDN = GetUserDn(username);

				var modList = new LdapModification[1];
				var attr = new LdapAttribute("userPassword", newPassword);
				modList[0] = new LdapModification(LdapModification.REPLACE, attr);

				connection.Modify(userDN, modList);

				return true;
			
		}
		catch (LdapException ex)
		{
			Console.WriteLine("Error: " + ex.Message);
			return false;
		}
	}
	private static string GetUserDn(string username)
	{
		try
		{
			var connection = new LdapConnection();

			connection.Connect(_server, _port);
			connection.Bind(_bindDn, _bindPassword);

			string searchFilter = "(cn=" + username + ")"; // uid özniteliğine göre arama yapıyoruz
			string[] attributesToReturn = new string[] { "DN", };

			LdapSearchConstraints constraints = new LdapSearchConstraints();
			constraints.ReferralFollowing = true;

			LdapSearchResults searchResults = connection.Search(
				_baseDn,
				LdapConnection.SCOPE_SUB,
				searchFilter,
				attributesToReturn,
				false,
				constraints
			);

			if (searchResults.hasMore())
			{
				LdapEntry entry = searchResults.next();
				return entry.DN;
			}
			else
			{
				return null;
			}

		}
		catch (LdapException ex)
		{
			Console.WriteLine("LDAP Error: " + ex.Message);
			return null;
		}
	}

	public void DeleteAccount(string username)
	{
		try
		{
			var ldapConnection = new LdapConnection();

			// LDAP sunucusuna bağlan
			ldapConnection.Connect(_server, _port);
			ldapConnection.Bind(_bindDn, _bindPassword);

			string userDN = GetUserDn(username);

			// Kullanıcı hesabını sil
			ldapConnection.Delete(userDN);

			Console.WriteLine("Delete Success");

		}
		catch (LdapException ex)
		{
			Console.WriteLine("LDAP Error: " + ex.LdapErrorMessage);
		}
		catch (Exception ex)
		{
			Console.WriteLine("Error: " + ex.Message);
		}
	}

	private static string GeneratePassword()
	{
		string newLDAPpassword = string.Empty;
		const string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		const string lowerChars = "abcdefghijklmnopqrstuvwxyz";
		const string numbers = "0123456789";
		const string allChars = upperChars + lowerChars + numbers;

		var random = new Random();
		var password = new StringBuilder();

		
		password.Append(upperChars[random.Next(upperChars.Length)]);
		password.Append(lowerChars[random.Next(lowerChars.Length)]);
		password.Append(numbers[random.Next(numbers.Length)]);

		
		for (int i = 3; i < 8; i++)
		{
			password.Append(allChars[random.Next(allChars.Length)]);
		}
		newLDAPpassword = password.ToString().ToCharArray().OrderBy(x => random.Next()).ToArray().ToString();
		newLDAPpassword = "{MD5}" + Convert.ToBase64String(ldapConf.ConvertHexStringToByteArray(ldapConf.MD5Sifrele(newLDAPpassword)));
		
		return newLDAPpassword;
	}
	public List<LdapUserClass> ListAllAccounts()
	{
		var accounts = new List<LdapUserClass>();

		try
		{
			var connection = new LdapConnection();

			connection.Connect(_server, _port);
			connection.Bind(_bindDn, _bindPassword);

			string filter = "(objectClass=person)";
			// MaxResults: number of accounts to come from the selected area
			var search = connection.Search(
				_baseDn,
				LdapConnection.SCOPE_SUB,
				filter,
				null,
				false,
				new LdapSearchConstraints()
				{
					MaxResults = 30000,
				}
			);
			Dictionary<string, string> veriler = new Dictionary<string, string>();
			while (search.hasMore())
			{
				LdapEntry nextEntry = null;
				try
				{
					nextEntry = search.next();
				}
				catch (LdapException e)
				{
					Console.WriteLine("Error: " + e.Message);
					continue;
				}

				LdapAttributeSet attributeSet = nextEntry.getAttributeSet();
				System.Collections.IEnumerator ienum = attributeSet.GetEnumerator();
				LdapUserClass useritem = new LdapUserClass();
				while (ienum.MoveNext())
				{
					LdapAttribute attribute = (LdapAttribute)ienum.Current;
					string attributeName = attribute.Name;
					string attributeVal = attribute.StringValue;

					if (attributeName == "cn")
					{
						useritem.cn = attributeVal;
					}
					else if (attributeName == "givenName")
					{
						useritem.givenName = attributeVal;
					}
					else if (attributeName == "sn")
					{
						useritem.sn = attributeVal;
					}
					else if (attributeName == "mail")
					{
						useritem.mail = attributeVal;
					}
					else if (attributeName == "userPassword")
					{
						useritem.userPassword = attributeVal;
					}
					else if (attributeName == "title")
					{
						useritem.title = attributeVal;
					}
					else if (attributeName == "telephoneNumber")
					{
						useritem.telephoneNumber = attributeVal;
					}
					else if (attributeName == "mobile")
					{
						useritem.mobile = attributeVal;
					}
					else if (attributeName == "jobUnit")
					{
						useritem.jobUnit = attributeVal;
					}
					else if (attributeName == "idNumber")
					{
						useritem.idNumber = attributeVal;
					}

				}

				accounts.Add(useritem);
			}
		}
		catch (LdapException e)
		{
			Console.WriteLine("LDAP Error : " + e.Message);
		}
		catch (Exception e)
		{
			Console.WriteLine("Error :  " + e.Message);
		}

		return accounts;
	}

	public void UpdateUser(string username, Dictionary<string, string> attributes)
	{
		try
		{
			var connection = new LdapConnection();

			connection.Connect(_server, _port);
			connection.Bind(_bindDn, _bindPassword);
			string userDN = GetUserDn(username);

			var modifications = new List<LdapModification>();

			foreach (var attribute in attributes)
			{
				var ldapAttribute = new LdapAttribute(attribute.Key, attribute.Value);
				var modification = new LdapModification(LdapModification.REPLACE, ldapAttribute);
				modifications.Add(modification);
			}

			connection.Modify(userDN, modifications.ToArray());
			Console.WriteLine("Update Success");


		}
		catch (LdapException ex)
		{
			Console.WriteLine("Error :  " + ex.Message);
		}

	}

	public struct LdapUserClass
	{
		public string username { get; set; }
		public string cn { get; set; }
		public string uid { get; set; }
		public string givenName { get; set; }
		public string sn { get; set; }
		public string mail { get; set; }
		public string idNumber { get; set; }
		public string userPassword { get; set; }
		public string title { get; set; }
		public string telephoneNumber { get; set; }
		public string mobile { get; set; }
		public string jobUnit { get; set; }

	}

}
