using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ModelService
{
    public class TokenModel
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string ClientId { get; set; }
        [Required]
        public string Value { get; set; }
        [Required]
        public DateTime CreatedDate { get; set; }
        [Required]
        public string UserId { get; set; }
        [Required]
        public DateTime LastModifiedDate { get; set; }
        [Required]
        public string EncryptionKeyRt { get; set; }
        public string EncryptionKeyJwt { get; set; }
        [ForeignKey("UserId")]
        public virtual ApplicationUser User { get; set; }
    }
}       
