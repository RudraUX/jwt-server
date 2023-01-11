namespace JWT_SER
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public string PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }

    }
}
