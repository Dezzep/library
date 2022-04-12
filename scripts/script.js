

function Book(title, author, pages, wasRead){   //constructor for book
  this.title = title;
  this.author = author;
  this.pages = pages;
  this.wasRead = wasRead;
  if (this.wasRead === false){
      this.wasRead = 'Not read yet';
      }
    else{
      this.wasRead = 'Finished Reading'
    }}

function addBookToLibrary(array) {    //every time a form is submitted, this should be called.
  for (i in array){
    console.log(array[i])
    console.log(array[i].title)

    const div = document.createElement("div");            
    const elementTitle = document.createElement("p");     //creates paragraphs to store content
    const elementAuthor = document.createElement("p");
    const elementPages = document.createElement("p");
    const elementRead = document.createElement("p");
    const elementButton = document.createElement("button");   //creates delete button
    elementButton.textContent = 'Delete'
    elementButton.id = [i]; // reasoning = to know where in myLibrary array to delete
    const title = document.createTextNode(`Book Title: ${array[i].title}`); //refers to book object constructor
    const author = document.createTextNode(`Author: ${array[i].author}`);
    const pages = document.createTextNode(`Pages: ${array[i].pages}`);
    const read = document.createTextNode(`${array[i].wasRead}`);

    elementTitle.appendChild(title);
    elementAuthor.appendChild(author);
    elementPages.appendChild(pages);
    elementRead.appendChild(read);

    
    
    div.style.background = 'red';
    div.setAttribute('class', 'cards');
    div.id = `book${i}`
    document.getElementById("container").appendChild(div);            //adds the elements and their contents
    document.getElementById(`book${i}`).appendChild(elementTitle);    //to the div
    document.getElementById(`book${i}`).appendChild(elementAuthor);
    document.getElementById(`book${i}`).appendChild(elementPages);
    document.getElementById(`book${i}`).appendChild(elementRead);
    document.getElementById(`book${i}`).appendChild(elementButton);
  }
}
// let duggler  =[
// book1 = new Book('hobbit', 'J.R.R. Tolkien', '295 pages', true),
// book2 = new Book('Taco', 'block', '25', false,)]


let myLibrary = [book1 = new Book('hobbit', 'J.R.R. Tolkien', '295 pages', true),
book2 = new Book('Taco', 'block', '25', false,)]
addBookToLibrary(myLibrary)


//let pppp = document.querySelector('#container .cards')

let delButton = document.querySelectorAll('#container .cards >button').forEach(div => div.onclick = (e) => {
  const removeFromArray = e.target.id // this selects the button which is created with a unique ID of n of the array
  myLibrary.splice(removeFromArray, 1);
  const deleting = e.target.parentElement; 
  deleting.remove();

})

const addForm = document.forms["book-form"];

addForm.addEventListener("submit", function(e){  // takes form input, WILL (ADDS TO ARRAY).

  e.preventDefault();
  let bookTitle = document.getElementById("book-title").value; 
  let authorName = document.getElementById("author").value;
  let pageCount = document.getElementById("pages").value;

  
  
  addForm.style.display="none";
  addForm.style.display="block";

  console.log(pageCount);
  console.log(authorName);
  console.log(bookTitle);

  addForm.reset();
});