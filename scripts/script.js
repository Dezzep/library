



function Book(title, author, pages, wasRead){
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

function addBookToLibrary(array) {
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
    elementButton.id = [i];
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
  const bleep = e.target.id
  myLibrary.splice(bleep, 1);
  const deleting = e.target.parentElement;
  console.log(deleting.id);
  console.log(myLibrary);
  

  
  
  
  

})

