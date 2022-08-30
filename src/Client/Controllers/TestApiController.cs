using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProvider.Client.Controllers
{
    /// <summary>
    /// Controller for testing API calls and the functionality for verifying that the scope of the token
    /// given and the ACR is correct etc. before proceeding or requesting step up etc.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class TestApiController : ControllerBase
    {
        // GET: api/<TestApiController>
        [HttpGet]
        [Authorize(AuthenticationSchemes = "Bearer", Policy = "Level1")]
        public IEnumerable<string> Get()
        {
            return new string[] { "value1", "value2" };
        }

        // GET api/<TestApiController>/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<TestApiController>
        [HttpPost]
        [Authorize(AuthenticationSchemes = "Bearer", Policy = "Level2")]
        public void Post([FromBody] string value)
        {

        }

        // PUT api/<TestApiController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE api/<TestApiController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
