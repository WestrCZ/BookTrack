using BookTrack.Api.Interfaces;
using BookTrack.Data;
using BookTrack.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace BookTrack.Api.Services;

public class BookService(AppDbContext dbContext) : IBookService
{
    public async Task<Book> CreateAsync(Book book, CancellationToken cancellationToken)
    {
        if (book == null)
            throw new ArgumentNullException("Book can't be null");
        else if (string.IsNullOrEmpty(book.Title))
            throw new Exception("Please fill in the Title.");
        else if (string.IsNullOrEmpty(book.Author))
            throw new Exception("Please fill in the Author.");
        else
        {
            book.Id = Guid.NewGuid();
            dbContext.Books.Add(book);
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        return await GetAsync(book.Id, cancellationToken);
    }
    public async Task<Book> GetAsync(Guid id, CancellationToken cancellationToken)
        => await dbContext.Books.FirstOrDefaultAsync(x => x.Id == id, cancellationToken)
            ?? throw new Exception("Book was not found.");
    public async Task<List<Book>> ListAsync(CancellationToken cancellationToken)
        => await dbContext.Books.ToListAsync(cancellationToken);
    public async Task<Book> UpdateAsync(Book book, CancellationToken cancellationToken)
    {
        if (book == null)
            throw new ArgumentNullException("Book can't be null");
        else if (string.IsNullOrEmpty(book.Title))
            throw new Exception("Please fill in the Title.");
        else if (string.IsNullOrEmpty(book.Author))
            throw new Exception("Please fill in the Author.");
        else
        {
            dbContext.Books.Update(book);
            await dbContext.SaveChangesAsync(cancellationToken);
            return book;

        }
    }
    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken)
    {
        var book = await GetAsync(id, cancellationToken);
        dbContext.Books.Remove(book);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
