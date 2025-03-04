using System.Collections;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using GetThingsDone.Models;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace GetThingsDone.Controllers {

    [Route("api/v1/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase {

        private readonly UserManager<UserModel> _userManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<UserModel> userManager, IConfiguration configuration) {
            _userManager = userManager;
            _configuration = configuration;
        }
    
        [HttpPost("login")]
        public async Task<ActionResult> Login([FromBody] LoginRecord request) {
            var user = await _userManager.FindByEmailAsync(request.email);
            if(user != null && await _userManager.CheckPasswordAsync(user, request.password)) {
                var token = GenerateJwtToken(user);
                return Ok( new { Token = token } );
            }
            return Unauthorized("Invalid credentials");
        }

        [HttpPost("register")]
        public async Task<ActionResult> Register([FromBody] RegisterRecord request) {

            var user = new UserModel { UserName = request.username, Email = request.email };
            var result = await _userManager.CreateAsync(user, request.password);

            if(result.Succeeded) {
                return Ok("Account created with successfully!");
            }

            return BadRequest(result.Errors);
        
        }

        [HttpPost("forgot-password")]
        public async Task<ActionResult> ForgotPassword([FromBody] ForgotPasswordRecord request) {

            var user = await _userManager.FindByEmailAsync(request.email);
            if(user == null) {
                return NotFound("Invalid e-mail account");
            }

            await _userManager.GeneratePasswordResetTokenAsync(user);

            return Ok();

        }
        
        private string GenerateJwtToken(UserModel user) {

            if(user.Email == null) {
                throw new Exception("Not found the user e-mail");
            }

            var claims = new [] {
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
    
            var jwtKey = _configuration["Jwt:Key"];
            
            if(jwtKey == null) {
                throw new Exception("Please admin, check if the JWT key is configurated in the settings file.");
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(8),
                signingCredentials: creds
            );
            
            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        public class GoogleCredentialRequest {
            public string Credential { get; set; } = string.Empty;
        }

        [HttpPost("login-google")]
        public async Task<ActionResult> LoginGoogle([FromBody] GoogleCredentialRequest credential) {
            try {
                
                var settings = new GoogleJsonWebSignature.ValidationSettings {
                    Audience = new List <string> { _configuration["Google:ClientId"] }
                };

                var payload = await GoogleJsonWebSignature.ValidateAsync(credential.Credential, settings);

                var user = await _userManager.FindByEmailAsync(payload.Email);

                if(user != null) {
                    var token = GenerateJwtToken(user);
                    return Ok( new { Token = token } );
                }
                
                var newUser = new UserModel {
                    UserName = payload.Name,
                    Email = payload.Email,
                    EmailConfirmed = payload.EmailVerified
                };

                var result = await _userManager.CreateAsync(newUser);
                
                if(result.Succeeded) {
                    var token = GenerateJwtToken(newUser);
                    return Ok( new { Token = token } );
                }
                
                return BadRequest(result.Errors);

            } catch (Exception ex) {
                return BadRequest( new { Message = ex.Message } );
            }
        } 

    }

}