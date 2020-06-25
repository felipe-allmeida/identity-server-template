using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer.Infra.Constants;
using IdentityServer.Infra.Data.Identity;
using IdentityServer4;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
namespace IdentityServer.Infra.Services
{
    public class IdentityClaimsProfileService : IProfileService
    {
        private readonly IUserClaimsPrincipalFactory<AppUser> _claimsFactory;
        private readonly UserManager<AppUser> _userManager;

        public IdentityClaimsProfileService(UserManager<AppUser> userManager, IUserClaimsPrincipalFactory<AppUser> claimsFactory)
        {
            _userManager = userManager;
            _claimsFactory = claimsFactory;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var sub = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(sub);
            //var claims = await _userManager.GetClaimsAsync(user);
            var principal = await _claimsFactory.CreateAsync(user);

            //var claims = principal.Claims.ToList();
            //claims = claims.Where(claim => context.RequestedClaimTypes.Contains(claim.Type)).ToList();
            //claims.Add(new Claim(JwtClaimTypes.GivenName, user.Name));
            //claims.Add(new Claim(IdentityServerConstants.StandardScopes.Email, user.Email));
            //// note: to dynamically add roles (ie. for users other than consumers - simply look them up by sub id
            ////claims.Add(new Claim(ClaimTypes.Role, Roles.Consumer)); // need this for role-based authorization - https://stackoverflow.com/questions/40844310/role-based-authorization-with-identityserver4

            ////context.Client            
            //context.IssuedClaims = claims.ToList();            

            context.IssuedClaims = await GetClaimsFromUser(user);             
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            //var sub = context.Subject.GetSubjectId();
            //var user = await _userManager.FindByIdAsync(sub);
            //context.IsActive = user != null;

            var subject = context.Subject;
            if (subject == null) throw new ArgumentNullException(nameof(context.Subject));

            var subjectId = subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(subjectId);

            context.IsActive = false;

            if (user != null)
            {
                if (_userManager.SupportsUserSecurityStamp)
                {
                    var security_stamp = subject.Claims.Where(c => c.Type == "security_stamp").Select(c => c.Value).SingleOrDefault();
                    if (security_stamp != null)
                    {
                        var db_security_stamp = await _userManager.GetSecurityStampAsync(user);
                        if (db_security_stamp != security_stamp)
                            return;
                    }
                }

                context.IsActive =
                    !user.LockoutEnabled ||
                    !user.LockoutEnd.HasValue ||
                    user.LockoutEnd <= DateTime.Now;
            }
        }

        private async Task<List<Claim>> GetClaimsFromUser(AppUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, user.Id),
                new Claim(JwtClaimTypes.PreferredUserName, user.UserName)
            };

            if (_userManager.SupportsUserEmail)
            {
                claims.AddRange(new[]
                {
                    new Claim(JwtClaimTypes.Email, user.Email),
                    new Claim(JwtClaimTypes.EmailVerified, user.EmailConfirmed ? "true" : "false", ClaimValueTypes.Boolean)
                });
            }

            if (_userManager.SupportsUserPhoneNumber && !string.IsNullOrWhiteSpace(user.PhoneNumber))
            {
                claims.AddRange(new[]
                {
                    new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber),
                    new Claim(JwtClaimTypes.PhoneNumberVerified, user.PhoneNumberConfirmed ? "true" : "false", ClaimValueTypes.Boolean)
                });
            }

            if (_userManager.SupportsUserClaim)
            {
                claims.AddRange(await _userManager.GetClaimsAsync(user));
            }

            if (_userManager.SupportsUserRole)
            {
                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(role => new Claim(JwtClaimTypes.Role, role)));
            }

            return claims;
        }
    }

}
