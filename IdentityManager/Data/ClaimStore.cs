using System.Collections.Generic;
using System.Security.Claims;

namespace IdentityManager.Data
{
    public static class ClaimStore
    {
        public static List<Claim> claimsList = new()
        {
            new ("Create", "Create"),
            new ("Edit", "Edit"),
            new ("Delete", "Delete")
        };
    }
}
