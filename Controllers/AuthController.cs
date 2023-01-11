using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace JWT_SER.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class AuthController : Controller
  {

    public static User user = new User();

    [HttpPost("register")]
    public async Task<ActionResult<User>> Register(UserDto req)
    {
      var passwordHash = CreatePasswordHash(req.Password, out byte[] salt);

      user.UserName = req.UserName;
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

      return Ok("Logged in");
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
      var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, passwordSalt, iterations, hashAlgorithm, keySize);

      return hashToCompare.SequenceEqual(Convert.FromHexString(passwordHash));
    }
  }
}
