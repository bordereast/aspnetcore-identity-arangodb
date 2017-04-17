using BorderEast.ArangoDB.Client;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BorderEast.ASPNetCore.Identity.ArangoDB.Stores
{

   public class RoleStore<TRole> : StoreBase, IRoleClaimStore<TRole>
        where TRole : IdentityRole {



        public RoleStore(IArangoClient arangoClient)
            : base(arangoClient) {

        }

        public Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken)) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Claims);
        }

        public Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken)) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            if (claim == null) {
                throw new ArgumentNullException(nameof(claim));
            }

            role.Claims.Add(claim);

            return Task.CompletedTask;
        }

        public Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken)) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            if (claim == null) {
                throw new ArgumentNullException(nameof(claim));
            }

            role.Claims.Remove(claim);

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            var result = await client.DB().InsertAsync(role);

            role = result.New;

            return !string.IsNullOrEmpty(result.Id)
                ? IdentityResult.Success
                : IdentityResult.Failed(new IdentityError() { Code = "Role Insert Failed" });
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            try {
                //ResourceResponse<Document> result = await documentClient.ReplaceDocumentAsync(GenerateDocumentUri(role.Id), document: role);
                //  var result = await client.ReplaceByIdAsync<TRole>(role.Id, role);
                var result = await client.DB().UpdateAsync(role.Key, role);
            }
            catch (Exception) {
                return IdentityResult.Failed();
            }

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();



            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            try {
                var result = await client.DB().DeleteAsync<TRole>(role.Key);
            }
            catch (Exception) {
                return IdentityResult.Failed();
            }

            return IdentityResult.Success;
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Name);
        }

        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            role.Name = roleName ?? throw new ArgumentNullException(nameof(roleName));

            return Task.CompletedTask;
        }

        public Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.NormalizedName);
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) {
                throw new ArgumentNullException(nameof(role));
            }

            role.NormalizedName = normalizedName ?? throw new ArgumentNullException(nameof(normalizedName));

            return Task.CompletedTask;
        }

        public async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (roleId == null) {
                throw new ArgumentNullException(nameof(roleId));
            }

            if (roleId.Contains("/")) {
                var ids = roleId.Split('/');
                roleId = ids[1];
            }

            var role = await client.DB().GetByKeyAsync<TRole>(roleId);

            return role;
        }

        public async Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken) {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (normalizedRoleName == null) {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            var role = await client.DB().GetByExampleAsync<TRole>(new { normalizedName = normalizedRoleName });


            return role.FirstOrDefault();
        }

        #region IDisposable Support

        public void Dispose() {
            // TODO: Workaround, gets disposed too early currently
            disposed = false;
        }

        #endregion
    }
}
