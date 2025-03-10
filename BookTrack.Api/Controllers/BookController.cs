using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using BookTrack.Api.Interfaces;
using BookTrack.Data.Entities;

namespace BookTrack.Api.Controllers;

[ApiController]
[Route("[controller]")]
public class BookController(IBookService bookService) : ControllerBase
{
    [HttpGet]
    [Authorize]
    public async Task<List<Book>> GetListAsync(CancellationToken cancellationToken) => await bookService.ListAsync(cancellationToken);
    [HttpGet("{id}")]
    [Authorize]
    public async Task<Book> GetByIdAsync(Guid id, CancellationToken cancellationToken) => await bookService.GetAsync(id, cancellationToken);
    [HttpPost]
    [Authorize]
    public async Task<Book> CreateAsync(Book book, CancellationToken cancellationToken) => await bookService.CreateAsync(book, cancellationToken);
    [HttpPut("{id}")]
    [Authorize]
    public async Task<Book> UpdateAsync(Guid id, Book book, CancellationToken cancellationToken)
    {
        book.Id = id;
        return await bookService.UpdateAsync(book, cancellationToken);
    }
    [HttpDelete("{id}")]
    [Authorize]
    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken) => await bookService.DeleteAsync(id, cancellationToken);

    [HttpGet("test")]
    [Authorize]
    public IActionResult Test() => Ok("Authenticated!");
}

