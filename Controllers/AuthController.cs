using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWT_SER.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public static User user = new User();

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }


        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var username = _userService.GetMyName();
            return Ok(username);
            // var userName = User?.Identity?.Name;
            // var userName2 = User.FindFirstValue(ClaimTypes.Name);
            // var role = User.FindFirstValue(ClaimTypes.Role);
            //
            // return Ok(new { userName, userName2, role });
        }


        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto req)
        {
            var passwordHash = CreatePasswordHash(req.Password, out byte[] salt); user.UserName = req.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = salt;

            return Ok(user);
        }
        [HttpPost("login")]
        public async Task<ActionResult> Login(UserDto req)
        {
            if (user.UserName != req.UserName)
            {
                return BadRequest("User not found!!");
            }

            if (!VerifyPassword(req.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong Password!!");
            }

            var token = CreateToken(user);

            return Ok(token);
        }



        //JWT Token
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
              {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role,"Admin")
              };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes
                (_configuration.GetSection("AppSettings:Token").Value));

            var cred = new SigningCredentials(key,
                SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
                );
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }


        //Hashing and Verifying Passwords
        const int keySize = 64;
        const int iterations = 350000;
        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;

        string CreatePasswordHash(string password, out byte[] passwordSalt)
        {
            passwordSalt = RandomNumberGenerator.GetBytes(keySize);

            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                passwordSalt,
                iterations,
                hashAlgorithm,
                keySize);

            return Convert.ToHexString(hash);
        }

        bool VerifyPassword(string password, string passwordHash, byte[] passwordSalt)
        {
            var hashToCompare = Rfc2898DeriveBytes.Pbkdf2
                (password,
                passwordSalt,
                iterations, hashAlgorithm,
                keySize);
            return hashToCompare.SequenceEqual(Convert.FromHexString(passwordHash));
        }
    }
}
