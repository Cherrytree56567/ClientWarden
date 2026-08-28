use iced::widget::{column, container, row, text, button};
use iced::{Element, Task, Theme, Color, Length, Background};
use iced::theme::Palette;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Page {
    AllItems,
    Favorites,
    Bin,
    Archived,
}

pub struct NavPanel {
    pub navPage: Page,
}

#[derive(Debug, Clone)]
pub enum Message {
    PageSelected(Page),
}

/*
 * I had to use AI mainly for the button func and stuff.
 */
impl NavPanel {
    pub fn new() -> Self {
        Self {
            navPage: Page::AllItems,
        }
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::PageSelected(page) => {
                self.navPage = page;
            }
        }
    }

    fn button<'a>(&self, label: &'a str, page: Page) -> Element<'a, Message> {
        let isSelected = self.navPage == page;

        button(text(label))
            .on_press(Message::PageSelected(page))
            .width(Length::Fill)
            .style(move |_theme, _status| button::Style {
                background: if (isSelected) {
                    Some(Background::Color(Color::from_rgb8(137, 180, 250)))
                } else {
                    None
                },
                text_color: if (isSelected) {
                    Color::from_rgb8(76, 79, 105)
                } else {
                    Color::from_rgb8(205, 214, 244)
                },
                ..Default::default()
            })
            .into()
    }

    pub fn view(&self) -> Element<'_, Message> {
        column![
            self.button("All Items", Page::AllItems),
            self.button("Favorites", Page::Favorites),
            self.button("Bin", Page::Bin),
            self.button("Archived", Page::Archived),
        ]
        .spacing(10)
        .width(150)
        .into()
    }
}