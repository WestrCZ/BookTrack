using BookTrack.Data.Entities;

namespace BookTrack.Api.Interfaces;

public interface IBookService
{
    Task<Book> CreateAsync(Book book, CancellationToken cancellationToken);
    Task<Book> GetAsync(Guid id, CancellationToken cancellationToken);
    Task<List<Book>> ListAsync(CancellationToken cancellationToken);
    Task<Book> UpdateAsync(Book book, CancellationToken cancellationToken);
    Task DeleteAsync(Guid id, CancellationToken cancellationToken);
}
